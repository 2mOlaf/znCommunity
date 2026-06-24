param (
	[Parameter(Mandatory = $false)]
    [bool] $BreakGlassNetwork,
	[Parameter(Mandatory = $false)]
    [bool] $BreakGlassIdentity,
	[Parameter(Mandatory = $false)]
    [string] $Mode,
	[Parameter(Mandatory = $false)]
    [bool] $DisableBlockRule
)

$ErrorActionPreference = "Stop"

function BreakGlass-Main {
    if ($BreakGlassNetwork) {
        BreakGlass-Network
    }
    
    if ($BreakGlassIdentity) {
        BreakGlass-Identity
    }
}

function BreakGlass-Network {
    try {
        BreakGlass-NetworkFirewall
    } catch {
        Write-Error "Network Firewall breakglass error: $($Error[0])"
    }
    
    try {
        BreakGlass-NetworkWfp
    } catch {
        Write-Error "Network WFP breakglass error: $($Error[0])"
    }
}

function BreakGlass-NetworkWfp {
    Add-Type -TypeDefinition $WfpBreakGlassCode -Language CSharp

    $runner = New-Object ZeroNetworks.Breakglass.WfpBreakglassRunner

    if ($runner.IsSublayerConfigured()) {
        $privilegedOnly = $Mode -eq "Privileged"

        $runner.AddAllowFilters($privilegedOnly);

        if ($DisableBlockRule) {
            $runner.RemoveExplicitBlocks();
        }
    }
}

function BreakGlass-NetworkFirewall {
    if ($Mode -eq "All" ) {
        netsh advfirewall firewall add rule name="Zero Networks Break Glass Inbound Allow All" dir=in action=allow protocol=any | Out-Null
    }

    if ($Mode -eq "Privileged") {
        netsh advfirewall firewall add rule name="Zero Networks Break Glass Inbound Allow Privileged" dir=in action=allow protocol=TCP localport=3389,5985,5986,9389,445 | Out-Null
    }

    netsh advfirewall firewall add rule name="Zero Networks Break Glass Outbound Allow All" dir=out action=allow protocol=any | Out-Null

    if ($DisableBlockRule) {
        $allrules = @(netsh advfirewall firewall show rule name=all) | Where-Object { $_ -match '^([^:]+):\s*(\S.*)$' } | ForEach-Object -Begin {
            $FirstRun = $true
            $HashProps = @{}
        } -Process {
            if (($Matches[1] -eq 'Rule Name') -and (!($FirstRun))) {
                New-Object -TypeName PSCustomObject -Property $HashProps
                $HashProps = @{}
            }

            $HashProps.$($Matches[1]) = $Matches[2];
            $FirstRun = $false
        } -End {
            New-Object -TypeName PSCustomObject -Property $HashProps
        }

        $blockrules = $allrules | Where-Object { $_.Enabled -eq "Yes" -and $_.Action -eq "Block" }

        foreach ($blockrule in $blockrules) {
            $ruleName = $blockrule.'Rule Name'
            netsh advfirewall firewall set rule name="$ruleName" new enable=no | Out-Null
        }
    }
}

function BreakGlass-Identity {
    try {
        secedit /export /cfg $env:temp\backup.cfg | out-null
        $secpolcontent = Get-Content $env:temp\backup.cfg
        $groupNames = (net localgroup | Select-Object -skip 4 | Where-Object { $_ -and $_ -match 'ZeroNetworks' }).replace("*", "")
    
        foreach ($groupName in $groupNames) {
            $secpolcontent = $secpolcontent -replace ",$groupname,", "," -replace "$groupName", "" -replace "$groupName", ""
        }
    
        $secpolcontent | Out-File $env:temp\backup.cfg
        secedit /configure /db C:\Windows\security\local.db /cfg $env:temp\backup.cfg /overwrite /log $env:temp\breakglass.log /quiet
    
        gpupdate.exe /force /Target:Computer
    } catch {
        Write-Error "Identity breakglass error: $($Error[0])"
    }
}

$WfpBreakGlassCode=@'
#pragma warning disable 0649

namespace ZeroNetworks.Breakglass
{
    using System;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;

    public class WfpBreakglassRunner
    {
        private static class Weights
        {
            public const byte DefaultAction = 1;
            public const byte ExplicitAllow = 5;
        }

        private static readonly Guid ProviderKey = new Guid("bf75ec5a-587c-43fc-b041-2f2283f45cfa");
        private static readonly Guid SubLayerKey = new Guid("9fa65c8e-9f83-4c8c-a51c-d08fbc241cf0");

        private static class ConditionKeys
        {
            public static readonly Guid IpProtocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
            public static readonly Guid IpLocalPort = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b");
        }

        private static readonly Guid[] OutboundLayers = { new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4") };
        private static readonly Guid[] InboundLayers = { new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f") };

        private readonly IntPtr _providerKeyPtr;
        private readonly IntPtr _engineHandle;

        public WfpBreakglassRunner()
        {
            _providerKeyPtr = BuildKeyPtr(ProviderKey);

            Native.FwpmSession0 session = new Native.FwpmSession0();
            session.sessionKey = Guid.NewGuid();
            session.flags = Native.FWPM_SESSION_FLAG.NONE;

            uint status = Native.FwpmEngineOpen0(null, (uint) Native.RPC_C_AUTHN.DEFAULT, IntPtr.Zero, ref session, out _engineHandle);
            if (status != 0)
            {
                throw new Exception("Failed to open engine: " + status);
            }
        }

        public bool IsSublayerConfigured()
        {
            Guid subLayerKey = SubLayerKey;

            IntPtr subLayer;
            uint status = Native.FwpmSubLayerGetByKey0(_engineHandle, ref subLayerKey, out subLayer);

            return status == 0;
        }

        private static IntPtr BuildKeyPtr(Guid key)
        {
            IntPtr keyPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
            Marshal.StructureToPtr(key, keyPtr, false);

            return keyPtr;
        }

        public void AddAllowFilters(bool allowPrivilegedOnly)
        {
            if (allowPrivilegedOnly)
            {
                Console.WriteLine("Adding privileged allow");
                AddAllowPrivilegedFilters();
            }
            else
            {
                Console.WriteLine("Adding inbound allow");
                AddAllowFilters("Inbound Allow All", InboundLayers, new Native.FwpmFilterCondition0[] { });
            }

            Console.WriteLine("Adding outbound allow");
            AddAllowFilters("Outbound Allow All", OutboundLayers, new Native.FwpmFilterCondition0[] { });
        }

        public void RemoveExplicitBlocks()
        {
            List<Guid> filterKeysToRemove = new List<Guid>();

            foreach (Native.FWPM_FILTER0 filter in EnumerateExistingFilters())
            {
                if (IsExplicitBlock(filter))
                {
                    filterKeysToRemove.Add(filter.FilterKey);
                }
            }

            if (filterKeysToRemove.Count > 0)
            {
                Console.WriteLine("Removing explicit blocks");

                RemoveFilters(filterKeysToRemove);
            }
        }

        private void AddAllowFilters(string tag, Guid[] layerKeys, Native.FwpmFilterCondition0[] conditions)
        {
            foreach (Guid layerKey in layerKeys)
            {
                AddAllowFilter(layerKey, tag, conditions);
            }
        }

        private void AddAllowPrivilegedFilters()
        {
            AddAllowFilters("Inbound Allow Privileged", InboundLayers, new Native.FwpmFilterCondition0[]
            {
                BuildProtocolCondition(6),
                BuildLocalPortCondition(3389),
                BuildLocalPortCondition(5985),
                BuildLocalPortCondition(5986),
                BuildLocalPortCondition(9389),
                BuildLocalPortCondition(445),
            });
        }

        private static Native.FwpmFilterCondition0 BuildProtocolCondition(byte protocol)
        {
            Native.FwpmFilterCondition0 condition = new Native.FwpmFilterCondition0();
            condition.MatchType = Native.FWP_MATCH.EQUAL;
            condition.FieldKey = ConditionKeys.IpProtocol;
            condition.ConditionValue = new Native.FwpValue0();
            condition.ConditionValue.Type = Native.FWP_DATA_TYPE.UINT8;
            condition.ConditionValue.Value.Uint8 = protocol;

            return condition;
        }

        private Native.FwpmFilterCondition0 BuildLocalPortCondition(ushort port)
        {
            Native.FwpmFilterCondition0 condition = new Native.FwpmFilterCondition0();
            condition.MatchType = Native.FWP_MATCH.EQUAL;
            condition.FieldKey = ConditionKeys.IpLocalPort;
            condition.ConditionValue = new Native.FwpValue0();
            condition.ConditionValue.Type = Native.FWP_DATA_TYPE.UINT16;
            condition.ConditionValue.Value.Uint16 = port;

            return condition;
        }

        private static bool IsExplicitBlock(Native.FWPM_FILTER0 filter)
        {
            return filter.Action.Type == Native.FWP_ACTION_TYPE.BLOCK &&
                   filter.Weight.Value.Uint8 > Weights.DefaultAction;
        }

        private void RemoveFilters(IEnumerable<Guid> filterKeysToRemove)
        {
            uint status = Native.FwpmTransactionBegin0(_engineHandle, 0);
            if (status != 0)
            {
                throw new Exception("Failed to begin transaction: " + status);
            }

            foreach (Guid filterKeyToRemove in filterKeysToRemove)
            {
                DeleteFilter(_engineHandle, filterKeyToRemove);
            }

            status = Native.FwpmTransactionCommit0(_engineHandle);
            if (status != 0)
            {
                throw new Exception("Failed to commit transaction: " + status);
            }
        }

        private IEnumerable<Native.FWPM_FILTER0> EnumerateExistingFilters()
        {
            Console.WriteLine("Scanning filters");

            IntPtr enumHandle;
            uint status = Native.FwpmFilterCreateEnumHandle0(_engineHandle, IntPtr.Zero, out enumHandle);
            if (status != 0)
            {
                throw new Exception("Failed to create filters enumerator handle: " + status);
            }

            uint numEntriesReturned;
            IntPtr entries;
            status = Native.FwpmFilterEnum0(_engineHandle, enumHandle, uint.MaxValue, out entries, out numEntriesReturned);
            if (status != 0)
            {
                throw new Exception("Failed to enumerate filters: " + status);
            }

            for (uint i = 0; i < numEntriesReturned; i++)
            {
                IntPtr entryPtr = new IntPtr(entries.ToInt64() + i * IntPtr.Size);
                IntPtr filterPtr = (IntPtr) Marshal.PtrToStructure(entryPtr, typeof(IntPtr));
                Native.FWPM_FILTER0 filter = (Native.FWPM_FILTER0) Marshal.PtrToStructure(filterPtr, typeof(Native.FWPM_FILTER0));

                if (filter.ProviderKey == IntPtr.Zero)
                {
                    continue;
                }

                Guid filterProviderKey = (Guid) Marshal.PtrToStructure(filter.ProviderKey, typeof(Guid));
                if (filterProviderKey != ProviderKey)
                {
                    continue;
                }

                yield return filter;
            }
        }

        private static void DeleteFilter(IntPtr engineHandle, Guid filterKey)
        {
            uint status = Native.FwpmFilterDeleteByKey0(engineHandle, ref filterKey);
            if (status != 0)
            {
                throw new Exception("Failed to remove filter " + filterKey + " :" + status);
            }
        }

        private void AddAllowFilter(Guid layerKey, string tag, IList<Native.FwpmFilterCondition0> conditions)
        {
            Native.FWPM_FILTER0 filter = new Native.FWPM_FILTER0();

            filter.ProviderKey = _providerKeyPtr;
            filter.FilterKey = Guid.NewGuid();
            filter.LayerKey = layerKey;
            filter.SubLayerKey = SubLayerKey;
            filter.Flags = Native.FWPM_FILTER_FLAG.PERSISTENT;
            filter.Action.Type = Native.FWP_ACTION_TYPE.PERMIT;
            filter.Action.CalloutKey = Guid.Empty;
            filter.Weight.Type = Native.FWP_DATA_TYPE.UINT8;
            filter.Weight.Value.Uint8 = Weights.ExplicitAllow;
            filter.DisplayData.Name = "Zero Networks Break Glass " + tag;
            filter.DisplayData.Description = "Zero Network Break Glass filter";
            filter.NumFilterConditions = (uint) conditions.Count;
            filter.FilterConditions = ListToPtr(conditions);

            ulong id;
            uint status = Native.FwpmFilterAdd0(_engineHandle, ref filter, IntPtr.Zero, out id);

            if (status != 0)
            {
                throw new Exception(string.Format("Failed to add filter {0}", filter.DisplayData.Name));
            }
        }

        private static IntPtr ListToPtr<T>(IList<T> items)
        {
            int itemSize = Marshal.SizeOf(typeof(T));

            IntPtr ptr = Marshal.AllocHGlobal(itemSize * items.Count);

            for (int i = 0; i < items.Count; i++)
            {
                IntPtr itemPtr = new IntPtr(ptr.ToInt64() + i * itemSize);

                Marshal.StructureToPtr(items[i], itemPtr, false);
            }

            return ptr;
        }

        private static class Native
        {
            public struct FWPM_FILTER0
            {
                public Guid FilterKey;
                public FWPM_DISPLAY_DATA0 DisplayData;
                public FWPM_FILTER_FLAG Flags;
                public IntPtr ProviderKey;
                public FwpByteBlob ProviderData;
                public Guid LayerKey;
                public Guid SubLayerKey;
                public FwpValue0 Weight;
                public uint NumFilterConditions;
                public IntPtr FilterConditions;
                public FwpmAction0 Action;
                public Union Context;
                public IntPtr Reserved;
                public ulong FilterId;
                public FwpValue0 EffectiveWeight;

                [StructLayout(LayoutKind.Explicit)]
                public struct Union
                {
                    [FieldOffset(0)] public ulong RawContext;
                    [FieldOffset(0)] public Guid ProviderContextKey;
                }
            }

            public struct FwpValue0
            {
                public FWP_DATA_TYPE Type;
                public Union Value;

                [StructLayout(LayoutKind.Explicit)]
                public struct Union
                {
                    [FieldOffset(0)] public byte Uint8;
                    [FieldOffset(0)] public ushort Uint16;
                    [FieldOffset(0)] public uint Uint32;
                    [FieldOffset(0)] public IntPtr Uint64;
                    [FieldOffset(0)] public sbyte Int8;
                    [FieldOffset(0)] public short Int16;
                    [FieldOffset(0)] public int Int32;
                    [FieldOffset(0)] public IntPtr Int64;
                    [FieldOffset(0)] public float Float32;
                    [FieldOffset(0)] public IntPtr Double64;
                    [FieldOffset(0)] public IntPtr ByteArray16;
                    [FieldOffset(0)] public IntPtr ByteBlob;
                    [FieldOffset(0)] public IntPtr Sid;
                    [FieldOffset(0)] public IntPtr Sd;
                    [FieldOffset(0)] public IntPtr TokenInformation;
                    [FieldOffset(0)] public IntPtr TokenAccessInformation;
                    [FieldOffset(0)] public IntPtr UnicodeString;
                    [FieldOffset(0)] public IntPtr ByteArray6;
                    [FieldOffset(0)] public IntPtr Range;
                }
            }

            public enum FWP_DATA_TYPE : uint
            {
                UINT8 = 0x00000001,
                UINT16 = 0x00000002,
            }

            public struct FwpmFilterCondition0
            {
                public Guid FieldKey;
                public FWP_MATCH MatchType;
                public FwpValue0 ConditionValue;
            }

            public enum FWP_MATCH
            {
                EQUAL = 0,
            }

            public struct FwpByteBlob
            {
                public uint Size;
                public IntPtr Data;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct FwpmAction0
            {
                [FieldOffset(0)] public FWP_ACTION_TYPE Type;
                [FieldOffset(4)] public Guid FilterType;
                [FieldOffset(4)] public Guid CalloutKey;
            }

            public enum FWP_ACTION_TYPE : uint
            {
                BLOCK = 0x00001001,
                PERMIT = 0x00001002,
            }

            public struct FWPM_DISPLAY_DATA0
            {
                [MarshalAs(UnmanagedType.LPWStr)] public string Name;
                [MarshalAs(UnmanagedType.LPWStr)] public string Description;
            }

            [Flags]
            public enum FWPM_FILTER_FLAG : uint
            {
                PERSISTENT = 0x00000001,
            }

            public enum RPC_C_AUTHN : uint
            {
                DEFAULT = 0xFFFFFFFF,
            }

            public enum FWPM_SESSION_FLAG : uint
            {
                NONE = 0x00000000,
            }

            public struct FwpmSession0
            {
                public Guid sessionKey;
                public FWPM_DISPLAY_DATA0 displayData;
                public FWPM_SESSION_FLAG flags;
                public uint txnWaitTimeoutInMSec;
                public uint processId;
                public IntPtr sid;
                [MarshalAs(UnmanagedType.LPWStr)] public string username;
                [MarshalAs(UnmanagedType.Bool)] public bool kernelMode;
            }

            [DllImport("FWPUCLNT.DLL")]
            public static extern uint FwpmEngineOpen0(
                [MarshalAs(UnmanagedType.LPWStr)] string serverName, uint authnService, IntPtr authIdentity, ref FwpmSession0 session, out IntPtr engineHandle);

            [DllImport("FWPUCLNT.DLL")]
            public static extern uint FwpmSubLayerGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr sublayer);

            [DllImport("FWPUCLNT.DLL")]
            internal static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);

            [DllImport("FWPUCLNT.DLL")]
            public static extern uint FwpmFilterCreateEnumHandle0(
                IntPtr engineHandle,
                IntPtr enumTemplate,
                out IntPtr enumHandle);

            [DllImport("FWPUCLNT.DLL")]
            public static extern uint FwpmFilterEnum0(
                IntPtr engineHandle,
                IntPtr enumHandle,
                uint numEntriesRequested,
                out IntPtr entries,
                out uint numEntriesReturned);

            [DllImport("FWPUCLNT.DLL")]
            internal static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);

            [DllImport("FWPUCLNT.DLL")]
            public static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

            [DllImport("FWPUCLNT.DLL")]
            public static extern uint FwpmTransactionCommit0(IntPtr engineHandle);
        }
    }
}
'@

BreakGlass-Main