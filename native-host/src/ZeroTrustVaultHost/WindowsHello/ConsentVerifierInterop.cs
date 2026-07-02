using System.Diagnostics;
using System.Runtime.InteropServices;
using Windows.Foundation;
using Windows.Security.Credentials.UI;
using ZeroTrustVaultHost.Diagnostics;

namespace ZeroTrustVaultHost.WindowsHello;

/// <summary>
/// Shows the Windows Hello consent dialog from a process that has no foreground
/// window of its own — which is exactly the case when the native host is
/// launched by Chrome's native-messaging subsystem (a child console process).
///
/// Per Microsoft's own documentation: "Methods that follow the Request naming
/// pattern, such as UserConsentVerifier requests, are not supported in desktop
/// apps because internally these methods use the Windows.UI.Popups class, which
/// requires that the thread have a CoreWindow object that isn't supported in
/// desktop apps." A console/native-messaging host NEVER has a CoreWindow, so the
/// windowless <c>UserConsentVerifier.RequestVerificationAsync</c> cannot show its
/// dialog at all from this process shape — this is not a focus quirk, it is
/// structural. The documented remedy is the COM interop
/// <c>IUserConsentVerifierInterop.RequestVerificationForWindowAsync</c>
/// (userconsentverifierinterop.h, IID 39E050C3-4E74-441A-8DC0-B81104DF949C),
/// which anchors the dialog to a real HWND that we create for this purpose.
///
/// Critical detail (found only after the anchor window showed as "not
/// responding" in testing): creating a raw Win32 window is not enough — the
/// window's OWNING THREAD must run a real message loop (GetMessage /
/// TranslateMessage / DispatchMessage), and that thread must be STA
/// (Thread.SetApartmentState(ApartmentState.STA)) so the WinRT async-operation
/// completion is dispatched back onto it correctly. Without a pump, Windows'
/// own hang detection flags the window as unresponsive, and the broker's
/// completion notification has nowhere reliable to be delivered, which explains
/// both the multi-second delays and the eventual "not responding" dialog seen
/// in testing. Everything here (window creation, COM activation, the request,
/// and the completion callback) now runs on one dedicated STA thread with an
/// active pump; the public async API awaits a TaskCompletionSource that the
/// pump thread signals when done.
///
/// Sources: learn.microsoft.com/windows/win32/api/userconsentverifierinterop/,
/// devblogs.microsoft.com/oldnewthing/20240925-00 ("Using the UserConsentVerifier
/// from a Win32 program"), github.com/microsoft/WindowsAppSDK discussion #1265.
/// </summary>
internal static class ConsentVerifierInterop
{
    private static readonly Guid IID_IUserConsentVerifierInterop =
        new("39E050C3-4E74-441A-8DC0-B81104DF949C");

    private static readonly Guid IID_IUnknown =
        new("00000000-0000-0000-C000-000000000046");

    // .NET 5+ removed support for InterfaceType.InterfaceIsIInspectable in classic
    // COM interop ("Marshalling as IInspectable is not supported in the .NET
    // runtime" — confirmed by direct testing). The documented workaround is to
    // declare the interface as InterfaceIsIUnknown (still fully supported) and
    // manually occupy the three IInspectable vtable slots (GetIids,
    // GetRuntimeClassName, GetTrustLevel) that sit between IUnknown and our real
    // method, so the vtable layout still lines up correctly. Every WinRT interface
    // is IUnknown(3) + IInspectable(3) + its own methods — that ABI shape is fixed
    // and version-independent; we never call the three stub methods.
    [ComImport]
    [Guid("39E050C3-4E74-441A-8DC0-B81104DF949C")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IUserConsentVerifierInterop
    {
        // ---- IInspectable vtable slots (3, 4, 5) — stubs only, never invoked ----
        void GetIids(out uint iidCount, out IntPtr iids);
        void GetRuntimeClassName(out IntPtr className);
        void GetTrustLevel(out int trustLevel);

        // ---- Real method (vtable slot 6) ----
        // The HSTRING message and the returned generic WinRT interface are both
        // declared as raw IntPtr: classic (non-CsWinRT) COM interop cannot marshal
        // UnmanagedType.HString or a CsWinRT-projected generic type directly
        // (confirmed by testing — both throw "invalid managed/unmanaged type
        // combination"). We marshal the message HSTRING manually with
        // WindowsCreateString/WindowsDeleteString, pass IID_IUnknown as riid (every
        // COM object satisfies IUnknown, so this never fails with E_NOINTERFACE),
        // and unwrap the returned pointer via CsWinRT's own supported
        // WinRT.MarshalInterface<T>.FromAbi — the same mechanism the
        // already-working windowless call relies on internally. All four native
        // parameters are declared explicitly (including the trailing out pointer)
        // rather than relying on ComImport's implicit "last out becomes the
        // return value" promotion, which only special-cases interface-typed
        // returns and does not apply cleanly here.
        void RequestVerificationForWindowAsync(
            IntPtr appWindow,
            IntPtr message,
            ref Guid riid,
            out IntPtr asyncOperation);
    }

    // ---- Win32 window + message-pump plumbing -----------------------------------

    // The anchor window previously used the stock "STATIC" system window class.
    // STATIC is documented as a display-only control class that does not
    // properly participate in the normal activation/focus chain (it is not
    // designed to receive keyboard focus at all) — using it as a repurposed
    // top-level window is very likely why activation did not correctly
    // propagate to the broker's OWNED dialog even after explicit
    // SetForegroundWindow/AttachThreadInput calls succeeded at the Win32 API
    // level. A properly registered window class with a real (if minimal)
    // window procedure is what every working native sample uses. We register
    // one lazily and use it instead.
    private static readonly WndProcDelegate s_wndProc = DefaultWndProc;
    private static bool s_classRegistered;
    private static readonly object s_classLock = new();
    private const string AnchorClassName = "ZtvHelloAnchorWindow";

    private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    private static IntPtr DefaultWndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam) =>
        DefWindowProcW(hWnd, msg, wParam, lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEXW
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        [MarshalAs(UnmanagedType.LPWStr)] public string? lpszMenuName;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpszClassName;
        public IntPtr hIconSm;
    }

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClassExW(ref WNDCLASSEXW lpwcx);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    /// <summary>
    /// Registers our own top-level window class exactly once per process.
    /// Safe to call repeatedly. The WndProcDelegate instance is kept in a static
    /// field so the GC never collects it while native code may still invoke it.
    /// </summary>
    private static void EnsureClassRegistered()
    {
        if (s_classRegistered) return;
        lock (s_classLock)
        {
            if (s_classRegistered) return;
            var wc = new WNDCLASSEXW
            {
                cbSize = (uint)Marshal.SizeOf<WNDCLASSEXW>(),
                style = 0,
                lpfnWndProc = Marshal.GetFunctionPointerForDelegate(s_wndProc),
                hInstance = GetModuleHandleW(null),
                lpszClassName = AnchorClassName,
            };
            ushort atom = RegisterClassExW(ref wc);
            if (atom == 0)
            {
                int err = Marshal.GetLastWin32Error();
                // 1410 = ERROR_CLASS_ALREADY_EXISTS — fine (e.g. re-registration
                // after some earlier partial init); anything else is logged but
                // we still proceed and let CreateWindowExW report the real error.
                if (err != 1410)
                    DiagnosticLog.Write("HELLO_INTEROP", $"RegisterClassExW failed, Win32 error {err}.");
            }
            s_classRegistered = true;
        }
    }

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWindowExW(
        uint dwExStyle, string lpClassName, string lpWindowName, uint dwStyle,
        int x, int y, int nWidth, int nHeight,
        IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    // The actual Windows Hello consent dialog is created by a SEPARATE broker
    // process (owned by our anchor window, but not our own window), and Windows
    // restricts which processes may steal foreground/input focus. Foregrounding
    // our own anchor window is not enough for the broker's dialog to grab focus
    // automatically. AllowSetForegroundWindow(ASFW_ANY) grants any process a
    // one-time right to foreground itself — the standard, documented technique
    // for exactly this "launch a helper dialog and let it take focus" scenario.
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllowSetForegroundWindow(int dwProcessId);

    private const int ASFW_ANY = -1;

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    // ---- Actively locating and focusing the broker's owned dialog ---------------
    // AllowSetForegroundWindow only grants permission; it does not guarantee the
    // broker's own code actually calls SetForegroundWindow, or that focus sticks.
    // The broker's consent dialog is created as a window OWNED by our anchor HWND
    // (the appWindow parameter passed to RequestVerificationForWindowAsync), so we
    // can find it precisely (not by guessing titles/process names) and force
    // focus onto it directly with the well-known AttachThreadInput technique,
    // which bypasses the normal SetForegroundWindow restrictions.

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, IntPtr lpdwProcessId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, [MarshalAs(UnmanagedType.Bool)] bool fAttach);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BringWindowToTop(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    private const uint GW_OWNER = 4;

    /// <summary>
    /// Finds a currently-visible top-level window owned by <paramref name="ownerHwnd"/>
    /// (i.e. the broker's consent dialog, not our invisible anchor) and forces
    /// foreground/input focus onto it using AttachThreadInput, which works even
    /// when plain SetForegroundWindow would be silently ignored by Windows'
    /// foreground-lock restrictions. Returns true if a target window was found
    /// and focused.
    /// </summary>
    private static bool TryFocusOwnedDialog(IntPtr ownerHwnd)
    {
        IntPtr found = IntPtr.Zero;
        EnumWindowsProc callback = (hWnd, _) =>
        {
            if (hWnd != ownerHwnd && IsWindowVisible(hWnd) && GetWindow(hWnd, GW_OWNER) == ownerHwnd)
            {
                found = hWnd;
                return false; // stop enumerating
            }
            return true; // continue
        };
        EnumWindows(callback, IntPtr.Zero);

        if (found == IntPtr.Zero) return false;
        if (GetForegroundWindow() == found) return true; // already focused

        uint myThreadId = GetCurrentThreadId();
        uint targetThreadId = GetWindowThreadProcessId(found, IntPtr.Zero);

        bool attached = targetThreadId != 0 && targetThreadId != myThreadId
            && AttachThreadInput(myThreadId, targetThreadId, true);
        try
        {
            BringWindowToTop(found);
            SetForegroundWindow(found);
        }
        finally
        {
            if (attached) AttachThreadInput(myThreadId, targetThreadId, false);
        }
        return true;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? lpModuleName);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    [DllImport("user32.dll")]
    private static extern int GetMessageW(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(ref MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessageW(ref MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern void PostQuitMessage(int nExitCode);

    // PostThreadMessage (not PostQuitMessage) is required to signal the pump
    // loop to exit: PostQuitMessage always posts to the CALLING thread's queue,
    // but under MTA the WinRT Completed callback is delivered on an arbitrary
    // thread-pool thread, not necessarily the dedicated pump thread — confirmed
    // by testing (the anchor window stayed on screen forever because the quit
    // signal never reached the pump thread's own queue). PostThreadMessage lets
    // us target the pump thread's captured ID explicitly, from whichever thread
    // the callback actually runs on.
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostThreadMessage(uint idThread, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    private const uint WM_QUIT = 0x0012;

    // Explicit WinRT runtime initialization (combase.dll). Confirmed by direct
    // testing: activating IUserConsentVerifierInterop via RoGetActivationFactory
    // fails with E_NOINTERFACE when the calling thread is STA (whether via
    // Thread.SetApartmentState or RoInitialize(RO_INIT_SINGLETHREADED)), but
    // succeeds as MTA — matching the ambient .NET thread-pool thread (implicitly
    // MTA) that this call originally worked from before a dedicated thread was
    // introduced. The window's own message pump requirement is independent of
    // COM apartment type, so MTA + an explicit pump gives us both: activation
    // succeeds, and the window still behaves instead of being flagged
    // "not responding".
    [DllImport("combase.dll", PreserveSig = true)]
    private static extern int RoInitialize(int initType);

    [DllImport("combase.dll")]
    private static extern void RoUninitialize();

    private const int RO_INIT_MULTITHREADED = 1;

    private const uint WS_POPUP         = 0x80000000;
    private const uint WS_EX_TOPMOST    = 0x00000008;
    private const uint WS_EX_TOOLWINDOW = 0x00000080;
    private const int  SW_SHOWNORMAL = 1;
    private const int  SM_CXSCREEN   = 0;
    private const int  SM_CYSCREEN   = 1;

    // ---- Raw WinRT activation (combase.dll) -------------------------------------
    // We go straight to the OS activation APIs rather than relying on managed
    // convenience helpers: System.Runtime.InteropServices.WindowsRuntime's
    // WindowsRuntimeMarshal.GetActivationFactory (the .NET Framework-era helper)
    // was removed from modern .NET's compatibility shim, and CsWinRT's
    // WinRT.ActivationFactory is an internal implementation detail not meant for
    // app code. RoGetActivationFactory is the stable, documented OS API that both
    // of those higher-level helpers are themselves built on (roapi.h, present on
    // every WinRT-capable Windows release since 8.0).

    [DllImport("combase.dll", PreserveSig = false)]
    private static extern void RoGetActivationFactory(
        IntPtr activatableClassId, ref Guid iid, out IntPtr factory);

    [DllImport("combase.dll", PreserveSig = false)]
    private static extern void WindowsCreateString(
        [MarshalAs(UnmanagedType.LPWStr)] string sourceString, int length, out IntPtr hstring);

    [DllImport("combase.dll")]
    private static extern int WindowsDeleteString(IntPtr hstring);

    /// <summary>
    /// Activates the IUserConsentVerifierInterop factory. Split out so
    /// <see cref="WarmUp"/> can trigger the same COM class activation ahead of
    /// time — activating a WinRT class for the first time in a process can
    /// itself take a noticeable moment, and that cost should be paid once at
    /// host startup, not on the user's critical path when they click Unlock.
    /// </summary>
    private static IUserConsentVerifierInterop ActivateFactory()
    {
        IntPtr classIdHandle = IntPtr.Zero;
        IntPtr factory = IntPtr.Zero;
        try
        {
            const string className = "Windows.Security.Credentials.UI.UserConsentVerifier";
            WindowsCreateString(className, className.Length, out classIdHandle);

            Guid factoryIid = IID_IUserConsentVerifierInterop;
            RoGetActivationFactory(classIdHandle, ref factoryIid, out factory);

            object obj = Marshal.GetObjectForIUnknown(factory);
            return (IUserConsentVerifierInterop)obj;
        }
        finally
        {
            if (factory != IntPtr.Zero) Marshal.Release(factory);
            if (classIdHandle != IntPtr.Zero) WindowsDeleteString(classIdHandle);
        }
    }

    /// <summary>
    /// Pre-activates the WinRT class used by the windowed interop path so the
    /// first real Unlock click does not pay a COM class-activation cold-start
    /// cost. Call once, fire-and-forget, right after the host starts. Safe to
    /// call multiple times; any failure here is silently absorbed — the real
    /// request will simply pay the (small) activation cost itself instead.
    /// </summary>
    public static void WarmUp()
    {
        try
        {
            var sw = Stopwatch.StartNew();
            _ = ActivateFactory();
            DiagnosticLog.Write("HELLO_INTEROP", $"Warm-up activation completed in {sw.ElapsedMilliseconds}ms.");
        }
        catch (Exception ex)
        {
            DiagnosticLog.Write("HELLO_INTEROP", $"Warm-up activation failed (non-fatal): {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Requests Windows Hello verification anchored to a transient helper window.
    /// Runs the window, the WinRT call, and its completion entirely on one
    /// dedicated STA thread with a real Win32 message pump — required for the
    /// broker to interact with the window and deliver the completion callback
    /// promptly (see class remarks). Returns the verification result, or null if
    /// the windowed interop path is unavailable (caller falls back to the
    /// windowless API, which never regresses behavior even though it cannot show
    /// a dialog from this process shape).
    /// </summary>
    public static Task<UserConsentVerificationResult?> TryRequestAsync(string message)
    {
        var tcs = new TaskCompletionSource<UserConsentVerificationResult?>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        // Deliberately do NOT call Thread.SetApartmentState(STA) here: doing so
        // makes .NET auto-run CoInitializeEx(APARTMENTTHREADED) before our code
        // starts, which pre-empts our own explicit RoInitialize call below and
        // locks the thread into STA — confirmed by testing to make
        // RoGetActivationFactory fail with E_NOINTERFACE for this specific
        // interface (it activated fine from the ambient MTA thread-pool thread
        // used previously, but not from an STA thread). We instead leave the
        // thread's apartment state untouched here and explicitly initialize it
        // as MTA ourselves inside PumpThreadMain, which matches the apartment
        // the activation already worked under while still giving this window
        // its own dedicated message pump (Win32 windows need a pump regardless
        // of COM apartment type — that part was never the issue).
        var thread = new Thread(() => PumpThreadMain(message, tcs))
        {
            IsBackground = true,
            Name = "ZtvHelloPump",
        };
        thread.Start();

        return tcs.Task;
    }

    private static void PumpThreadMain(string message, TaskCompletionSource<UserConsentVerificationResult?> tcs)
    {
        var totalSw = Stopwatch.StartNew();
        IntPtr hwnd = IntPtr.Zero;
        IntPtr messageHandle = IntPtr.Zero;
        bool roInitialized = false;
        uint pumpThreadId = GetCurrentThreadId();
        try
        {
            // HRESULT: S_OK (0) or S_FALSE (1, already initialized) are success;
            // only a negative HRESULT is a real failure.
            int hr = RoInitialize(RO_INIT_MULTITHREADED);
            roInitialized = hr >= 0;
            DiagnosticLog.Write("HELLO_INTEROP", $"RoInitialize(MTA) hr=0x{hr:X8} on pump thread.");

            int screenW = GetSystemMetrics(SM_CXSCREEN);
            int screenH = GetSystemMetrics(SM_CYSCREEN);
            const int w = 360, h = 120;
            int x = screenW > 0 ? Math.Max(0, (screenW - w) / 2) : 100;
            int y = screenH > 0 ? Math.Max(0, (screenH - h) / 2) : 100;

            // WS_EX_TOOLWINDOW hides this anchor from the taskbar and Alt+Tab —
            // it only needs to exist as a real on-screen HWND for the broker to
            // anchor its dialog to; it was never meant to appear as its own app
            // entry (confirmed by user report showing a taskbar context menu for
            // "ZeroTrustVaultHost"). On-screen positioning (not this flag) was
            // what fixed the earlier invisible-dialog bug; the two are independent.
            //
            // Uses our own registered window class (AnchorClassName), not the
            // stock "STATIC" system class — STATIC is a display-only control
            // class that does not participate in the normal keyboard focus /
            // activation chain, which is very likely why the broker's owned
            // dialog never properly received activation even when
            // SetForegroundWindow/AttachThreadInput succeeded at the API level.
            EnsureClassRegistered();
            hwnd = CreateWindowExW(
                WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                AnchorClassName, "Zero-Trust Vault - Windows Hello", WS_POPUP,
                x, y, w, h,
                IntPtr.Zero, IntPtr.Zero, GetModuleHandleW(null), IntPtr.Zero);

            if (hwnd == IntPtr.Zero)
            {
                DiagnosticLog.Write("HELLO_INTEROP", "CreateWindowExW failed; falling back to windowless API.");
                tcs.TrySetResult(null);
                return;
            }

            ShowWindow(hwnd, SW_SHOWNORMAL);
            SetForegroundWindow(hwnd);
            DiagnosticLog.Write("HELLO_INTEROP", $"[t+{totalSw.ElapsedMilliseconds}ms] Anchor window created on STA pump thread.");

            IUserConsentVerifierInterop interop;
            try
            {
                interop = ActivateFactory();
            }
            catch (Exception ex)
            {
                DiagnosticLog.Write("HELLO_INTEROP", $"RoGetActivationFactory failed: {ex.GetType().Name}: {ex.Message}");
                tcs.TrySetResult(null);
                return;
            }
            DiagnosticLog.Write("HELLO_INTEROP", $"[t+{totalSw.ElapsedMilliseconds}ms] Factory activated.");

            WindowsCreateString(message, message.Length, out messageHandle);
            Guid riid = IID_IUnknown; // always satisfied; avoids computing the
                                      // true parameterized IAsyncOperation<T> IID
            IntPtr asyncOpPtr;

            // Grant the about-to-be-created broker dialog (a separate process) the
            // right to foreground/focus itself, so the user can interact with it
            // immediately instead of having to click it first.
            AllowSetForegroundWindow(ASFW_ANY);
            interop.RequestVerificationForWindowAsync(hwnd, messageHandle, ref riid, out asyncOpPtr);
            DiagnosticLog.Write("HELLO_INTEROP", $"[t+{totalSw.ElapsedMilliseconds}ms] RequestVerificationForWindowAsync submitted.");

            if (asyncOpPtr == IntPtr.Zero)
            {
                DiagnosticLog.Write("HELLO_INTEROP", "RequestVerificationForWindowAsync returned a null operation pointer.");
                tcs.TrySetResult(null);
                return;
            }

            // Actively find and focus the broker's dialog (owned by our anchor
            // window) rather than relying solely on it self-activating: retry for
            // a few seconds since the dialog may take a moment to appear, and
            // re-assert focus a couple of times in case something briefly steals
            // it back. Cancelled as soon as the operation completes.
            using var focusCts = new CancellationTokenSource();
            _ = Task.Run(async () =>
            {
                for (int attempt = 0; attempt < 25 && !focusCts.IsCancellationRequested; attempt++)
                {
                    try
                    {
                        bool focused = TryFocusOwnedDialog(hwnd);
                        if (focused) DiagnosticLog.Write("HELLO_INTEROP", $"[t+{totalSw.ElapsedMilliseconds}ms] Focused broker dialog (attempt {attempt}).");
                    }
                    catch (Exception ex)
                    {
                        DiagnosticLog.Write("HELLO_INTEROP", $"TryFocusOwnedDialog failed: {ex.GetType().Name}: {ex.Message}");
                    }
                    try { await Task.Delay(200, focusCts.Token); } catch (OperationCanceledException) { break; }
                }
            });

            // Wrap the raw ABI pointer using CsWinRT's own supported marshaling —
            // the same mechanism the already-working windowless call uses
            // internally — rather than classic COM interop, which cannot marshal
            // this generic WinRT type directly.
            var op = WinRT.MarshalInterface<IAsyncOperation<UserConsentVerificationResult>>.FromAbi(asyncOpPtr);

            // Subscribe to completion rather than `await`ing here: under MTA this
            // callback can be delivered on an arbitrary thread-pool thread, not
            // necessarily the pump thread, so we must not block the pump thread
            // waiting on it — instead, whichever thread the callback runs on
            // posts WM_QUIT directly to the CAPTURED pump thread ID (not
            // PostQuitMessage, which only targets the calling thread's own
            // queue — confirmed by testing to be the reason the anchor window
            // previously never closed).
            op.Completed = (asyncInfo, status) =>
            {
                try
                {
                    var result = asyncInfo.GetResults();
                    DiagnosticLog.Write("HELLO_INTEROP", $"[t+{totalSw.ElapsedMilliseconds}ms] Windowed verification result: {result}.");
                    tcs.TrySetResult(result);
                }
                catch (Exception ex)
                {
                    DiagnosticLog.Write("HELLO_INTEROP", $"Completion handler failed: {ex.GetType().Name}: {ex.Message}");
                    tcs.TrySetResult(null);
                }
                finally
                {
                    try { focusCts.Cancel(); } catch (ObjectDisposedException) { }
                    PostThreadMessage(pumpThreadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero);
                }
            };

            // Real Win32 message loop — this is what was missing before, and is
            // required both for the broker to interact with the anchor window
            // (instead of it being flagged "not responding") and for the
            // Completed callback above to actually be delivered promptly.
            while (GetMessageW(out MSG msg, IntPtr.Zero, 0, 0) > 0)
            {
                TranslateMessage(ref msg);
                DispatchMessageW(ref msg);
            }
            DiagnosticLog.Write("HELLO_INTEROP", $"[t+{totalSw.ElapsedMilliseconds}ms] Message pump exited.");
        }
        catch (Exception ex)
        {
            DiagnosticLog.Write("HELLO_INTEROP", $"Windowed verification failed, will fall back: {ex.GetType().Name}: {ex.Message}");
            tcs.TrySetResult(null);
        }
        finally
        {
            if (messageHandle != IntPtr.Zero) WindowsDeleteString(messageHandle);
            if (hwnd != IntPtr.Zero) DestroyWindow(hwnd);
            if (roInitialized) RoUninitialize();
            tcs.TrySetResult(null); // no-op if already set; guarantees the caller never hangs
        }
    }
}
