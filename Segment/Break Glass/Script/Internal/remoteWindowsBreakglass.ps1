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
        netsh advfirewall firewall add rule name="Zero Networks Break Glass Inbound Allow RDP" dir=in action=allow protocol=TCP localport=3389 | Out-Null
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
                AddAllowRdpFilters();
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

        private void AddAllowRdpFilters()
        {
            AddAllowFilters("Inbound Allow RDP", InboundLayers, new Native.FwpmFilterCondition0[]
            {
                BuildProtocolCondition(6),
                BuildLocalPortCondition(3389),
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
# SIG # Begin signature block
# MII9NgYJKoZIhvcNAQcCoII9JzCCPSMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAAlpVhXNmC0pl8
# ujMrGKqsiG4GctfoabATndZrExfnGaCCIfgwggXMMIIDtKADAgECAhBUmNLR1FsZ
# lUgTecgRwIeZMA0GCSqGSIb3DQEBDAUAMHcxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jvc29mdCBJZGVu
# dGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAy
# MDAeFw0yMDA0MTYxODM2MTZaFw00NTA0MTYxODQ0NDBaMHcxCzAJBgNVBAYTAlVT
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jv
# c29mdCBJZGVudGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRo
# b3JpdHkgMjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALORKgeD
# Bmf9np3gx8C3pOZCBH8Ppttf+9Va10Wg+3cL8IDzpm1aTXlT2KCGhFdFIMeiVPvH
# or+Kx24186IVxC9O40qFlkkN/76Z2BT2vCcH7kKbK/ULkgbk/WkTZaiRcvKYhOuD
# PQ7k13ESSCHLDe32R0m3m/nJxxe2hE//uKya13NnSYXjhr03QNAlhtTetcJtYmrV
# qXi8LW9J+eVsFBT9FMfTZRY33stuvF4pjf1imxUs1gXmuYkyM6Nix9fWUmcIxC70
# ViueC4fM7Ke0pqrrBc0ZV6U6CwQnHJFnni1iLS8evtrAIMsEGcoz+4m+mOJyoHI1
# vnnhnINv5G0Xb5DzPQCGdTiO0OBJmrvb0/gwytVXiGhNctO/bX9x2P29Da6SZEi3
# W295JrXNm5UhhNHvDzI9e1eM80UHTHzgXhgONXaLbZ7LNnSrBfjgc10yVpRnlyUK
# xjU9lJfnwUSLgP3B+PR0GeUw9gb7IVc+BhyLaxWGJ0l7gpPKWeh1R+g/OPTHU3mg
# trTiXFHvvV84wRPmeAyVWi7FQFkozA8kwOy6CXcjmTimthzax7ogttc32H83rwjj
# O3HbbnMbfZlysOSGM1l0tRYAe1BtxoYT2v3EOYI9JACaYNq6lMAFUSw0rFCZE4e7
# swWAsk0wAly4JoNdtGNz764jlU9gKL431VulAgMBAAGjVDBSMA4GA1UdDwEB/wQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTIftJqhSobyhmYBAcnz1AQ
# T2ioojAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwFAAOCAgEAr2rd5hnn
# LZRDGU7L6VCVZKUDkQKL4jaAOxWiUsIWGbZqWl10QzD0m/9gdAmxIR6QFm3FJI9c
# Zohj9E/MffISTEAQiwGf2qnIrvKVG8+dBetJPnSgaFvlVixlHIJ+U9pW2UYXeZJF
# xBA2CFIpF8svpvJ+1Gkkih6PsHMNzBxKq7Kq7aeRYwFkIqgyuH4yKLNncy2RtNwx
# AQv3Rwqm8ddK7VZgxCwIo3tAsLx0J1KH1r6I3TeKiW5niB31yV2g/rarOoDXGpc8
# FzYiQR6sTdWD5jw4vU8w6VSp07YEwzJ2YbuwGMUrGLPAgNW3lbBeUU0i/OxYqujY
# lLSlLu2S3ucYfCFX3VVj979tzR/SpncocMfiWzpbCNJbTsgAlrPhgzavhgplXHT2
# 6ux6anSg8Evu75SjrFDyh+3XOjCDyft9V77l4/hByuVkrrOj7FjshZrM77nq81YY
# uVxzmq/FdxeDWds3GhhyVKVB0rYjdaNDmuV3fJZ5t0GNv+zcgKCf0Xd1WF81E+Al
# GmcLfc4l+gcK5GEh2NQc5QfGNpn0ltDGFf5Ozdeui53bFv0ExpK91IjmqaOqu/dk
# ODtfzAzQNb50GQOmxapMomE2gj4d8yu8l13bS3g7LfU772Aj6PXsCyM2la+YZr9T
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggapMIIEkaADAgECAhMzAAF5CVV4
# lxQzu/ipAAAAAXkJMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDQwHhcNMjYwNTI3MTgxMTQ2WhcNMjYwNTMw
# MTgxMTQ2WjBrMQswCQYDVQQGEwJJTDERMA8GA1UECBMIVGVsIEF2aXYxETAPBgNV
# BAcTCFRlbCBBdml2MRowGAYDVQQKExFaZXJvIE5ldHdvcmtzIEx0ZDEaMBgGA1UE
# AxMRWmVybyBOZXR3b3JrcyBMdGQwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQCbQid4cGnIXFuk+u6okLR89Zcmq3Z72sk2oeDiNBgqib1rP82v56/46w2C
# EkT30XJs1PwPPVlC0u64cBLI3vFPPY4KzOY3SEhoRS8rrwYocjSX3VwI8BWgwmZP
# qo9nVC4v0n3lOPq3sy0io8DHLC9cRh1lsA7bXRgwYvgx9s5XtF3MwOHenFrE7dsT
# dtygG5oFJ86eafV2T9N3T/Uj0m+PGlJ8/Vdvdf3GBDMWRYLdbSoOO7YKqaaV27n7
# KZguXmuLGZOu0mZczi63mIXicBhda/ohNKHleNA6mLZb7I0uZEan8zSGZzmHh2Xx
# BC6CDVVK0vHXLFL2H886S1xlWrvWzn3Uay0/KWismIwgM9b2PZmS7CHtYSIVcbuV
# KMD1HUZReMa6kIYVubig81hNkp7HAZ45Al1FWaTEV1Pp2Euc1u/KMs9beQQP1Suo
# HmixSSvi7EsARr1Btxfc7kw/VU2cueMyo2M455D0uzi6W/K+h2rK4QFsOENEFzrV
# CZwQ15cCAwEAAaOCAdUwggHRMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
# MDwGA1UdJQQ1MDMGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhsrBgEEAYI3YYGwosY4
# g9jRjh+BtaSjBsGi+2swHQYDVR0OBBYEFJwF2lKPw0lXlVWXXJ5Jc4WSlk3dMB8G
# A1UdIwQYMBaAFJrxVHd1DIcWN0agrN55+fR/wXjpMGcGA1UdHwRgMF4wXKBaoFiG
# Vmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MElEJTIwVmVyaWZpZWQlMjBDUyUyMEVPQyUyMENBJTIwMDQuY3JsMHQGCCsGAQUF
# BwEBBGgwZjBkBggrBgEFBQcwAoZYaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBFT0Ml
# MjBDQSUyMDA0LmNydDBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMA0GCSqGSIb3DQEBDAUAA4ICAQBdjL66HLDy6angzB6L3Dmo24J9Wqw1bby0
# Devr9otwGL4O8EV1Ydsx1BjclVdTdh6o0d/SHxQjFB2QEyVawq4YqYPsBX9qtOOG
# fs7W8seXi06JahuaGyeOf4gxBwk15+hwPszVXsqL6yocUKsLVjyCKZpG0YET83Un
# a2g5p9Lwd8EDlqsVb59Emm2YxdO5wfnYRveMOuNtWW5Qe/XoYuRDpS/f0NiW196l
# KTrcklw8zLgsOlbWMCT/JI/Nn9mYCS7xNnpjPZW86arW9wxoqyce/UTlxv6KEzdY
# /gFw66+yITUW6d02QDG6CZYiCUeWFpaRItijPIocPwcll+rkIQZ7ONQcT0hlc/CZ
# oHgB1MF+JCu2FXZLI1qqMEoLxoGi/sNzG2y1wDIevZov+Ygm6Feqr/rQcutNK/SS
# b8GBTCnKgtgEhCN3yN2M/k1SJFXTaEilZuuA7XkcACweqhZEEg/44yOKJifzwIqR
# dIIvViMdVRIylkbAKUNxmQJq78TuK9/hfNM3fvpkgScQb6HOZDGYfsohgFA+NLUi
# 7WKsZ2BNVSzqjVlXQBa8MaloNgPCrbOSYlObSUTwB+XO0WHJdUDf4E+DWo+jcXhD
# N2ouRGY0+Jx1bwZAshq+nB+OY7VTxiiq7pB5hVbDI9ahd2/9V3FuH62+mo7QJQe8
# qEdJN7WQdzCCBqkwggSRoAMCAQICEzMAAXkJVXiXFDO7+KkAAAABeQkwDQYJKoZI
# hvcNAQEMBQAwWjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjErMCkGA1UEAxMiTWljcm9zb2Z0IElEIFZlcmlmaWVkIENTIEVPQyBD
# QSAwNDAeFw0yNjA1MjcxODExNDZaFw0yNjA1MzAxODExNDZaMGsxCzAJBgNVBAYT
# AklMMREwDwYDVQQIEwhUZWwgQXZpdjERMA8GA1UEBxMIVGVsIEF2aXYxGjAYBgNV
# BAoTEVplcm8gTmV0d29ya3MgTHRkMRowGAYDVQQDExFaZXJvIE5ldHdvcmtzIEx0
# ZDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAJtCJ3hwachcW6T67qiQ
# tHz1lyardnvayTah4OI0GCqJvWs/za/nr/jrDYISRPfRcmzU/A89WULS7rhwEsje
# 8U89jgrM5jdISGhFLyuvBihyNJfdXAjwFaDCZk+qj2dULi/SfeU4+rezLSKjwMcs
# L1xGHWWwDttdGDBi+DH2zle0XczA4d6cWsTt2xN23KAbmgUnzp5p9XZP03dP9SPS
# b48aUnz9V291/cYEMxZFgt1tKg47tgqpppXbufspmC5ea4sZk67SZlzOLreYheJw
# GF1r+iE0oeV40DqYtlvsjS5kRqfzNIZnOYeHZfEELoINVUrS8dcsUvYfzzpLXGVa
# u9bOfdRrLT8paKyYjCAz1vY9mZLsIe1hIhVxu5UowPUdRlF4xrqQhhW5uKDzWE2S
# nscBnjkCXUVZpMRXU+nYS5zW78oyz1t5BA/VK6geaLFJK+LsSwBGvUG3F9zuTD9V
# TZy54zKjYzjnkPS7OLpb8r6HasrhAWw4Q0QXOtUJnBDXlwIDAQABo4IB1TCCAdEw
# DAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwPAYDVR0lBDUwMwYKKwYBBAGC
# N2EBAAYIKwYBBQUHAwMGGysGAQQBgjdhgbCixjiD2NGOH4G1pKMGwaL7azAdBgNV
# HQ4EFgQUnAXaUo/DSVeVVZdcnklzhZKWTd0wHwYDVR0jBBgwFoAUmvFUd3UMhxY3
# RqCs3nn59H/BeOkwZwYDVR0fBGAwXjBcoFqgWIZWaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENT
# JTIwRU9DJTIwQ0ElMjAwNC5jcmwwdAYIKwYBBQUHAQEEaDBmMGQGCCsGAQUFBzAC
# hlhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29m
# dCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVPQyUyMENBJTIwMDQuY3J0MFQGA1Ud
# IARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wDQYJKoZIhvcNAQEMBQAD
# ggIBAF2MvrocsPLpqeDMHovcOajbgn1arDVtvLQN6+v2i3AYvg7wRXVh2zHUGNyV
# V1N2HqjR39IfFCMUHZATJVrCrhipg+wFf2q044Z+ztbyx5eLTolqG5obJ45/iDEH
# CTXn6HA+zNVeyovrKhxQqwtWPIIpmkbRgRPzdSdraDmn0vB3wQOWqxVvn0SabZjF
# 07nB+dhG94w6421ZblB79ehi5EOlL9/Q2JbX3qUpOtySXDzMuCw6VtYwJP8kj82f
# 2ZgJLvE2emM9lbzpqtb3DGirJx79ROXG/ooTN1j+AXDrr7IhNRbp3TZAMboJliIJ
# R5YWlpEi2KM8ihw/ByWX6uQhBns41BxPSGVz8JmgeAHUwX4kK7YVdksjWqowSgvG
# gaL+w3MbbLXAMh69mi/5iCboV6qv+tBy600r9JJvwYFMKcqC2ASEI3fI3Yz+TVIk
# VdNoSKVm64DteRwALB6qFkQSD/jjI4omJ/PAipF0gi9WIx1VEjKWRsApQ3GZAmrv
# xO4r3+F80zd++mSBJxBvoc5kMZh+yiGAUD40tSLtYqxnYE1VLOqNWVdAFrwxqWg2
# A8Kts5JiU5tJRPAH5c7RYcl1QN/gT4Naj6NxeEM3ai5EZjT4nHVvBkCyGr6cH45j
# tVPGKKrukHmFVsMj1qF3b/1XcW4frb6ajtAlB7yoR0k3tZB3MIIHKDCCBRCgAwIB
# AgITMwAAABcnRQkLi4evxgAAAAAAFzANBgkqhkiG9w0BAQwFADBjMQswCQYDVQQG
# EwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTQwMgYDVQQDEytN
# aWNyb3NvZnQgSUQgVmVyaWZpZWQgQ29kZSBTaWduaW5nIFBDQSAyMDIxMB4XDTI2
# MDMyNjE4MTEzMVoXDTMxMDMyNjE4MTEzMVowWjELMAkGA1UEBhMCVVMxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjErMCkGA1UEAxMiTWljcm9zb2Z0IElE
# IFZlcmlmaWVkIENTIEVPQyBDQSAwNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAILHZP4DD2YqAZXMn5OrQ8yfj0beK0ixilvHsKUtJEcV7VEQt09xnWwi
# pY6GxJ/LrLKoRqkKUYf0l70VcDVxCBm++lBuSD5AidUuv/QQ+tUELCsz3qVtEjY/
# E14LBcb0uzJbaEbopCCKe0OY0IGjjOkMivfvumVV1KWJmbpQHusfCa8GdHTZBPq2
# euparaKHMHqVElVMTO6HQ5p/Mgx4ydgzT7H697kQ4sd1+Kr4deIx/0lvtgse1iDI
# ciIkDttNYuoVIsZpOHtmVvFuwtcD3U46ugSm/s6PMW67e2SkL0V+UDgOnYS6rj6o
# +bFSp8an5NfSAtEmn00k7PMguNxMPeuQUUVvFS/XHKDpq+K8UMu2goGEzZN3Xfy6
# YTWk05pxqe5Ji08ch5AeYHqFoWLrhq8sEvBNMCb9FuK3zrRwVdHvbCr7lCHiFKZ7
# MeopcRFY+lUF74A+sngipz5o94yYiSgJZlA7bYecs0VQVJeOLDIhuC+Uf8sgAkSp
# Np9PPENmAqGUtTvOvqDCyrdY2lxhAjo27FafCHdVUMPIXuidCoqzkuXtuV5U3Rjx
# W+qATjmmnIFu/Co39G6fl8wIJHPdpgxjSRmEo73Z4/u3jMepnltAwCBnS0TY/P+N
# vTCLKRQX89yg6qqTe9UuJENiy3q93cYQw3MylRS9By8Ebjr4I4hvAgMBAAGjggHc
# MIIB2DAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYE
# FJrxVHd1DIcWN0agrN55+fR/wXjpMFQGA1UdIARNMEswSQYEVR0gADBBMD8GCCsG
# AQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVw
# b3NpdG9yeS5odG0wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwEgYDVR0TAQH/
# BAgwBgEB/wIBADAfBgNVHSMEGDAWgBTZQSmwDw9jbO9p1/XNKZ6kSGow5jBwBgNV
# HR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVkJTIwQ29kZSUyMFNpZ25pbmclMjBQ
# Q0ElMjAyMDIxLmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwSUQl
# MjBWZXJpZmllZCUyMENvZGUlMjBTaWduaW5nJTIwUENBJTIwMjAyMS5jcnQwDQYJ
# KoZIhvcNAQEMBQADggIBAJB1Whn9TSbfyXaIppkWWzFq+m2mg4vJpHVr1krZNIXW
# Q6cUmEwOx7oqQKCy96iISNdNVzpe3zogoefvo2TmpkHQFe/aIxFDaCIAmZi9lyay
# 2hmp8HYzcp3nCcmFQk60X9voeypJ6VjqeGsXTrOivWUOYNCLEFlwsH3NHX5EpCyj
# WN6Q3Fi5ST4do3eTVLnuqTQ7/9huTBTSYQsJbTg3m8gIxnHlPlzs2r/u4u9tWEJ0
# Pt/ZtmkDhTu86QHWigHgBoRHemOgnQxp3ksXKLo1r2n1m7+Gst46NTkUi1LljGyq
# +V9fEBOEnXvoKaRiy0pGbK1IdnsmEpF9Xp71l+2T84Nv8IrikZUBWqw5/jffttAa
# s4ccJDci832CadS4OHwl29uF6hY8fEg3UYHmxSJjnzi1c3vF0PwsJKxGom9Dx7tr
# eBlZOBWK6BGzVBar43Qb02N7okeU3UKMl6GB74fk8aS0mNr6O4YSvQ/66RKRwvqp
# pnEVBOHdIMjvWW9b77duX8TN3pI7w31R3D6t6jK9EcLJOJKymVlBIFNUl0+ajeoK
# ka7IcW0+jkIGff8U9OKol3cz0Eeiop3Qb0qaDp8ZwC8XCcs1cDaSi/vbvBGWMvfK
# l+ovuIBP9ienG6XpHAdGVw5/10MaDVFG+v3Y0/8JZVchvryB5Hau9T82x+a2MXXA
# MIIHnjCCBYagAwIBAgITMwAAAAeHozSje6WOHAAAAAAABzANBgkqhkiG9w0BAQwF
# ADB3MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MUgwRgYDVQQDEz9NaWNyb3NvZnQgSWRlbnRpdHkgVmVyaWZpY2F0aW9uIFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMjAwHhcNMjEwNDAxMjAwNTIwWhcNMzYw
# NDAxMjAxNTIwWjBjMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMTQwMgYDVQQDEytNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ29kZSBT
# aWduaW5nIFBDQSAyMDIxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# svDArxmIKOLdVHpMSWxpCFUJtFL/ekr4weslKPdnF3cpTeuV8veqtmKVgok2rO0D
# 05BpyvUDCg1wdsoEtuxACEGcgHfjPF/nZsOkg7c0mV8hpMT/GvB4uhDvWXMIeQPs
# DgCzUGzTvoi76YDpxDOxhgf8JuXWJzBDoLrmtThX01CE1TCCvH2sZD/+Hz3RDwl2
# MsvDSdX5rJDYVuR3bjaj2QfzZFmwfccTKqMAHlrz4B7ac8g9zyxlTpkTuJGtFnLB
# GasoOnn5NyYlf0xF9/bjVRo4Gzg2Yc7KR7yhTVNiuTGH5h4eB9ajm1OCShIyhrKq
# gOkc4smz6obxO+HxKeJ9bYmPf6KLXVNLz8UaeARo0BatvJ82sLr2gqlFBdj1sYfq
# Of00Qm/3B4XGFPDK/H04kteZEZsBRc3VT2d/iVd7OTLpSH9yCORV3oIZQB/Qr4nD
# 4YT/lWkhVtw2v2s0TnRJubL/hFMIQa86rcaGMhNsJrhysLNNMeBhiMezU1s5zpus
# f54qlYu2v5sZ5zL0KvBDLHtL8F9gn6jOy3v7Jm0bbBHjrW5yQW7S36ALAt03QDpw
# W1JG1Hxu/FUXJbBO2AwwVG4Fre+ZQ5Od8ouwt59FpBxVOBGfN4vN2m3fZx1gqn52
# GvaiBz6ozorgIEjn+PhUXILhAV5Q/ZgCJ0u2+ldFGjcCAwEAAaOCAjUwggIxMA4G
# A1UdDwEB/wQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU2UEpsA8P
# Y2zvadf1zSmepEhqMOYwVAYDVR0gBE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEW
# M2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5
# Lmh0bTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFMh+0mqFKhvKGZgEByfPUBBPaKiiMIGEBgNVHR8EfTB7MHmg
# d6B1hnNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3Nv
# ZnQlMjBJZGVudGl0eSUyMFZlcmlmaWNhdGlvbiUyMFJvb3QlMjBDZXJ0aWZpY2F0
# ZSUyMEF1dGhvcml0eSUyMDIwMjAuY3JsMIHDBggrBgEFBQcBAQSBtjCBszCBgQYI
# KwYBBQUHMAKGdWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMv
# TWljcm9zb2Z0JTIwSWRlbnRpdHklMjBWZXJpZmljYXRpb24lMjBSb290JTIwQ2Vy
# dGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDIwLmNydDAtBggrBgEFBQcwAYYhaHR0
# cDovL29uZW9jc3AubWljcm9zb2Z0LmNvbS9vY3NwMA0GCSqGSIb3DQEBDAUAA4IC
# AQB/JSqe/tSr6t1mCttXI0y6XmyQ41uGWzl9xw+WYhvOL47BV09Dgfnm/tU4ieeZ
# 7NAR5bguorTCNr58HOcA1tcsHQqt0wJsdClsu8bpQD9e/al+lUgTUJEV80Xhco7x
# dgRrehbyhUf4pkeAhBEjABvIUpD2LKPho5Z4DPCT5/0TlK02nlPwUbv9URREhVYC
# tsDM+31OFU3fDV8BmQXv5hT2RurVsJHZgP4y26dJDVF+3pcbtvh7R6NEDuYHYihf
# mE2HdQRq5jRvLE1Eb59PYwISFCX2DaLZ+zpU4bX0I16ntKq4poGOFaaKtjIA1vRE
# lItaOKcwtc04CBrXSfyL2Op6mvNIxTk4OaswIkTXbFL81ZKGD+24uMCwo/pLNhn7
# VHLfnxlMVzHQVL+bHa9KhTyzwdG/L6uderJQn0cGpLQMStUuNDArxW2wF16QGZ1N
# tBWgKA8Kqv48M8HfFqNifN6+zt6J0GwzvU8g0rYGgTZR8zDEIJfeZxwWDHpSxB5F
# J1VVU1LIAtB7o9PXbjXzGifaIMYTzU4YKt4vMNwwBmetQDHhdAtTPplOXrnI9SI6
# HeTtjDD3iUN/7ygbahmYOHk7VB7fwT4ze+ErCbMh6gHV1UuXPiLciloNxH6K4aMf
# ZN1oLVk6YFeIJEokuPgNPa6EnTiOL60cPqfny+Fq8UiuZzGCGpQwghqQAgEBMHEw
# WjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEr
# MCkGA1UEAxMiTWljcm9zb2Z0IElEIFZlcmlmaWVkIENTIEVPQyBDQSAwNAITMwAB
# eQlVeJcUM7v4qQAAAAF5CTANBglghkgBZQMEAgEFAKBeMBAGCisGAQQBgjcCAQwx
# AjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMC8GCSqGSIb3DQEJBDEiBCA3
# pnPx5UEUbXhGX+KdS6nFEAQ8OHYhoNPhB4ftNe3bYDANBgkqhkiG9w0BAQEFAASC
# AYCFkqICyvRcYnSO2wwmeiKsMvJFmY66Re5g7SUenpsNM5/i2wqz66WqDNDhQOfb
# kHi6e5kObNMXXc7zOLJRwdkBBcbXKpajbGLPJlpApunO6bRG8ptSXlSQoILq46DZ
# VUxtUlZBlUBZiWmqkQhw+Mt8WnDrmN4cy2F42SM+hdN/l6lCMxZXUARYdjDWL6Dy
# AwoZTaAoqQYhh0lYOS03N6jw4NOsqT9T6rBEgiu2XdRYysMPIqQ99hjsYOkljJGm
# HxfCDhObAz58dmt8q4EOPnCchypo2ouHVRPMOTDq/8DYE4aX+8ndXIfcYgYKmMbp
# ajkLSsvPqx0tP4bc/SWkob6/43FiXsJIuFN9Q5Io//mSV8CM3xCr7jBJHrjQaKLe
# uuelZBlz+YvkJJMuee6Pg1Z6AuXXhsgcdcK3ReKEAq+20IhWpk+AOc1OCrL6GTv3
# RVn1NHnzF5VTls0zxH+3rYib/EqU4+BbUskLIk/F0NCO6car22gKrj2fDfCq7RhB
# PiOhghgUMIIYEAYKKwYBBAGCNwMDATGCGAAwghf8BgkqhkiG9w0BBwKgghftMIIX
# 6QIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBYgYLKoZIhvcNAQkQAQSgggFRBIIBTTCC
# AUkCAQEGCisGAQQBhFkKAwEwMTANBglghkgBZQMEAgEFAAQg+iTLU8qeabhnVJuy
# FHaYbY5GgeTgmRT7qW45oBulQPcCBmoXZgwTQxgTMjAyNjA1MjgxMDU5MzkuNDE4
# WjAEgAIB9KCB4aSB3jCB2zELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUG
# A1UECxMeblNoaWVsZCBUU1MgRVNOOjdBMDAtMDVFMC1EOTQ3MTUwMwYDVQQDEyxN
# aWNyb3NvZnQgUHVibGljIFJTQSBUaW1lIFN0YW1waW5nIEF1dGhvcml0eaCCDyEw
# ggeCMIIFaqADAgECAhMzAAAABeXPD/9mLsmHAAAAAAAFMA0GCSqGSIb3DQEBDAUA
# MHcxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# SDBGBgNVBAMTP01pY3Jvc29mdCBJZGVudGl0eSBWZXJpZmljYXRpb24gUm9vdCBD
# ZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAyMDAeFw0yMDExMTkyMDMyMzFaFw0zNTEx
# MTkyMDQyMzFaMGExCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWVzdGFt
# cGluZyBDQSAyMDIwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnnzn
# UmP94MWfBX1jtQYioxwe1+eXM9ETBb1lRkd3kcFdcG9/sqtDlwxKoVIcaqDb+omF
# io5DHC4RBcbyQHjXCwMk/l3TOYtgoBjxnG/eViS4sOx8y4gSq8Zg49REAf5huXhI
# kQRKe3Qxs8Sgp02KHAznEa/Ssah8nWo5hJM1xznkRsFPu6rfDHeZeG1Wa1wISvlk
# pOQooTULFm809Z0ZYlQ8Lp7i5F9YciFlyAKwn6yjN/kR4fkquUWfGmMopNq/B8U/
# pdoZkZZQbxNlqJOiBGgCWpx69uKqKhTPVi3gVErnc/qi+dR8A2MiAz0kN0nh7SqI
# NGbmw5OIRC0EsZ31WF3Uxp3GgZwetEKxLms73KG/Z+MkeuaVDQQheangOEMGJ4pQ
# ZH55ngI0Tdy1bi69INBV5Kn2HVJo9XxRYR/JPGAaM6xGl57Ei95HUw9NV/uC3yFj
# rhc087qLJQawSC3xzY/EXzsT4I7sDbxOmM2rl4uKK6eEpurRduOQ2hTkmG1hSuWY
# BunFGNv21Kt4N20AKmbeuSnGnsBCd2cjRKG79+TX+sTehawOoxfeOO/jR7wo3liw
# kGdzPJYHgnJ54UxbckF914AqHOiEV7xTnD1a69w/UTxwjEugpIPMIIE67SFZ2PMo
# 27xjlLAHWW3l1CEAFjLNHd3EQ79PUr8FUXetXr0CAwEAAaOCAhswggIXMA4GA1Ud
# DwEB/wQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUa2koOjUvSGNA
# z3vYr0npPtk92yEwVAYDVR0gBE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEWM2h0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0
# bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMA
# QTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFMh+0mqFKhvKGZgEByfPUBBP
# aKiiMIGEBgNVHR8EfTB7MHmgd6B1hnNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL2NybC9NaWNyb3NvZnQlMjBJZGVudGl0eSUyMFZlcmlmaWNhdGlvbiUy
# MFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIwMjAuY3JsMIGUBggr
# BgEFBQcBAQSBhzCBhDCBgQYIKwYBBQUHMAKGdWh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwSWRlbnRpdHklMjBWZXJpZmlj
# YXRpb24lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDIwLmNy
# dDANBgkqhkiG9w0BAQwFAAOCAgEAX4h2x35ttVoVdedMeGj6TuHYRJklFaW4sTQ5
# r+k77iB79cSLNe+GzRjv4pVjJviceW6AF6ycWoEYR0LYhaa0ozJLU5Yi+LCmcrdo
# vkl53DNt4EXs87KDogYb9eGEndSpZ5ZM74LNvVzY0/nPISHz0Xva71QjD4h+8z2X
# MOZzY7YQ0Psw+etyNZ1CesufU211rLslLKsO8F2aBs2cIo1k+aHOhrw9xw6JCWON
# NboZ497mwYW5EfN0W3zL5s3ad4Xtm7yFM7Ujrhc0aqy3xL7D5FR2J7x9cLWMq7eb
# 0oYioXhqV2tgFqbKHeDick+P8tHYIFovIP7YG4ZkJWag1H91KlELGWi3SLv10o4K
# Gag42pswjybTi4toQcC/irAodDW8HNtX+cbz0sMptFJK+KObAnDFHEsukxD+7jFf
# EV9Hh/+CSxKRsmnuiovCWIOb+H7DRon9TlxydiFhvu88o0w35JkNbJxTk4MhF/Kg
# aXn0GxdH8elEa2Imq45gaa8D+mTm8LWVydt4ytxYP/bqjN49D9NZ81coE6aQWm88
# TwIf4R4YZbOpMKN0CyejaPNN41LGXHeCUMYmBx3PkP8ADHD1J2Cr/6tjuOOCztfp
# +o9Nc+ZoIAkpUcA/X2gSMkgHAPUvIdtoSAHEUKiBhI6JQivRepyvWcl+JYbYbBh7
# pmgAXVswggeXMIIFf6ADAgECAhMzAAAAWGXN6z+h1/zSAAAAAABYMA0GCSqGSIb3
# DQEBDAUAMGExCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWVzdGFtcGlu
# ZyBDQSAyMDIwMB4XDTI1MTAyMzIwNDY1NVoXDTI2MTAyMjIwNDY1NVowgdsxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jv
# c29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVT
# Tjo3QTAwLTA1RTAtRDk0NzE1MDMGA1UEAxMsTWljcm9zb2Z0IFB1YmxpYyBSU0Eg
# VGltZSBTdGFtcGluZyBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQCdeDSkdpDs9UCWWf4dlmskVwugpt6SFbXIv5A0FSAUVSyNkgpqqo3i
# ggmwkzemzSsk1I7ud0I1G5kNfZaC6vcCTvt5euWgFepmY7plVd4M1EIuV1bgDT81
# +PMntdeR0SGOvzWCFcSlHvML7Bto036w9LHMsBkF6JsMU/tfCznBfRm0iw3Vrb5e
# rlu9aneREzK3CyROO6dGB4tkv+0GnbfslV1E8UBD2NhEqkKpQGj+/XGMEtEJXc9q
# UqOcZ9vcw3hTuNXKqJ8UdKFydbkIRFGgGZRrqzKAPMVKvx7eD3dM80sVSK9QTQaY
# t9tflx4PUa3UVxnrH8ktUBPOTn4FYdszHAkhWRU9OpJIyNDopMp1yerekfRzgAUm
# n+CW9ymrRT1/NkiMkYa92mKyGVGXvtFC1SFKPEe8KfcsL/GpBDA4dJAOwaHo1fYP
# RF+xLIS1MAHIBp77bDUcHJMNNyaVM0sS5At4KPWA0F0haPRY5jIO2OND/yJNZjp7
# LW9v2oeWMiPkeAid1Pk/0xiTZWDZ7uEpRk0E1sD+GyAGy6hn4hfz1a+MQ31psX3V
# Lg4lW6KeYqws78wtueXuKS4PR03qgDRh7DINCdyzXawz0c627vZAD9NmV5+9byv3
# G0xcBihCVwaOyTxbhRztx+pWpsg+N2hzxnEHMtxdxXI/inlzIvC+QwIDAQABo4IB
# yzCCAccwHQYDVR0OBBYEFHKNTcV6vhXFcn6GM9xEmfGdEgmwMB8GA1UdIwQYMBaA
# FGtpKDo1L0hjQM972K9J6T7ZPdshMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFB1YmxpYyUy
# MFJTQSUyMFRpbWVzdGFtcGluZyUyMENBJTIwMjAyMC5jcmwweQYIKwYBBQUHAQEE
# bTBrMGkGCCsGAQUFBzAChl1odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NlcnRzL01pY3Jvc29mdCUyMFB1YmxpYyUyMFJTQSUyMFRpbWVzdGFtcGluZyUy
# MENBJTIwMjAyMC5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEF
# BQcDCDAOBgNVHQ8BAf8EBAMCB4AwZgYDVR0gBF8wXTBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMAgGBmeBDAEEAjANBgkqhkiG9w0BAQwFAAOCAgEA
# e+vEiJUXWIdxe/GslMIPx461s9Rsr3H4vPvSJh6GH4bRSg4xwx/ThAPq1A9N5nke
# EYRORyfStoMnk2l9tEG4oQffWvFtkr3ujXYpEM0nc27h49pQikf9NxbPw8tU4IQL
# LBLFsSAQbbSTLJ0Zzjpzn3W1fOl+QkNySOhivKlp6t15AtFAf0tqhNhl90DMyj4P
# LQ7UPMUmQXlieyYAzyW32vU21d0WN1sUwJtXl1q7riZXbazXzoDxSaL6Xbf35R7R
# xslAjKRaEiWGFaHFCCiSyofPuSnYYVkAB7JJOYg5A5bJc4DwkDxMhInKfckM6BK2
# /nzc/dXRBIAtPolcMJbboVXbTxUYkzOS/RLbaI5Nkn+hqZOmTxHMPyhZPyl9t7Wr
# +T9vE+JdhFvOmz3prlg6SjufRV2jrUM4mEv+aGTTVjfjyCrq+Eb9VNx0YeHWsKTA
# 4zTkHfkBlmr0C0+l9HMmKesfPMZHH6vp8Pdxxgw8wxf83B3aKvOumHXvZ9BxJ/V8
# zC/AiGZ8fgZYkn6Z/UcDq5egA5UHJySC5e+WPyA+LtPYRLpFTz5Cyx+pM1MkqOwG
# F5Ypa/ZbgRJV6fYvuULPuLv0WED7SSnTJcmdjB3NZLSi9Mg1Qsg2bNXIxxJSbla5
# V/xhnfdwC53Y6mvo3X5G4tkNq8O+OJ6GUjl0f4YTLnoxggdGMIIHQgIBATB4MGEx
# CzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWVzdGFtcGluZyBDQSAyMDIw
# AhMzAAAAWGXN6z+h1/zSAAAAAABYMA0GCWCGSAFlAwQCAQUAoIIEnzARBgsqhkiG
# 9w0BCRACDzECBQAwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3
# DQEJBTEPFw0yNjA1MjgxMDU5MzlaMC8GCSqGSIb3DQEJBDEiBCCkhoq1JL67TGj4
# Ip+MCbGB1O8sdvB8TKcGLmZCwVER+DCBuQYLKoZIhvcNAQkQAi8xgakwgaYwgaMw
# gaAEIMUiVLuyB9D7ACjVxZtbP5Y3r1UF2znyFutqf3X1ouhxMHwwZaRjMGExCzAJ
# BgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWVzdGFtcGluZyBDQSAyMDIwAhMz
# AAAAWGXN6z+h1/zSAAAAAABYMIIDYQYLKoZIhvcNAQkQAhIxggNQMIIDTKGCA0gw
# ggNEMIICLAIBATCCAQmhgeGkgd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo3QTAwLTA1RTAtRDk0NzE1MDMG
# A1UEAxMsTWljcm9zb2Z0IFB1YmxpYyBSU0EgVGltZSBTdGFtcGluZyBBdXRob3Jp
# dHmiIwoBATAHBgUrDgMCGgMVAJ1keRvbp6twXY7ra8J1lR9RK8RcoGcwZaRjMGEx
# CzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWVzdGFtcGluZyBDQSAyMDIw
# MA0GCSqGSIb3DQEBCwUAAgUA7cKNUDAiGA8yMDI2MDUyODA5NDU1MloYDzIwMjYw
# NTI5MDk0NTUyWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDtwo1QAgEAMAoCAQAC
# AgkXAgH/MAcCAQACAhLsMAoCBQDtw97QAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwG
# CisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEL
# BQADggEBAGh7h8bfaLqkT1SawUqlVq5i5ilX7FthDQ1gHCzgrMQzSE/hrBrRVSYr
# bmt1E7URgiC7k76vc7+r93qbnE2Wyl5NVgkP5clPRTMh+EjpL2WlNwEj361ctMve
# TVZA0ibqfc4rwL2VuRS582dWa1q4fsj3kItzFH1Y0URJyQtiR3uTooJmvv3/5Jlw
# LRc8t51fqXcWCdIiK2Q1bl49viAhwZkj+jKKaYGKbmdH7QgLBGDdKjqEyO70CfRR
# Ed9qsT0+5mI31HvFDZFUZ3VSVJGemyA0uS+7lZV6K5f2pcT2sSANZ/PtfawOAK0l
# Bt/o7SEP3RRelJYNsINztZ3ddP1WrzowDQYJKoZIhvcNAQEBBQAEggIAFVF5JBej
# gufmrbuB7Fv2w1boV9ldZQrOYUcxcpaPyKzHqh2fRiaJ+3xrURYYp1trk08gBp/D
# ZGsFCSU6/oTx57FLyPXd9NED12uMukWioUMf7XDmRSunmWESN1tGqsnnDva/Fvmw
# ORrjDpf5qp4I7fNtZ61ZBLOOqMSr6Zo82eVtDleqclDPHTcCSAiZ7dG717rVKJed
# mXQxRF4fqm0J7WSmgtrIm28YabhJk5AR/W+Tm25l8e3bmsf8EK19FmURBr5o2eCR
# WAJoFthoQnuHjcUa5u5CEtZOBBiRbjw7AcTjbtGIm8U2MnbS2M/FcxV6dDrHL1nS
# fzAf3H+r1DrAmd+aeocnjlJzWMNGgyXqCXwZvl+XpAko+zQMdfmoivhLjRoh7/f/
# M/iF+VVm4AqExELsZpcQB/Djm2nFHSCD6MNfv7K+TGbvKR++G1p5fzwxeeM4yxL9
# L/1I7oEeSECBxm4Clb9NO/W9N05y+4Gwp2xiujucvDem7KYSvThrdGUvhg+GngMR
# fKdZPh+dADp8fcyucf4zTCuPvzSkzOtDsCW+ejkv+/IcUmkaI3CgWifjbBCoBCJx
# I5cwsLbCoPu6XtK4vHiyYWTKzMq8bWE7xh9o7sJzYGGhDEQoQBD/RP3zgUKEupV+
# w2/9rPlAipFHYVZi4wkRVtvUKKWznTZrJ2c=
# SIG # End signature block
