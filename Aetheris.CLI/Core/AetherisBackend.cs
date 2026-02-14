using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Aetheris.CLI.Core
{
    public class AetherisBackend
    {
        private const string LibName = "aetheris_ffi";

        [StructLayout(LayoutKind.Sequential)]
        public struct BinaryBuffer
        {
            public IntPtr Ptr;
            public UIntPtr Len;
        }

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int aetheris_init();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern BinaryBuffer aetheris_get_node_status_bin();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void aetheris_free_buffer(BinaryBuffer buffer);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int aetheris_start_node(ushort port, string dbPath);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aetheris_is_initialized();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aetheris_create_wallet();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aetheris_import_wallet(string mnemonic);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr aetheris_get_genesis_phrase();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void aetheris_free_string(IntPtr ptr);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr aetheris_get_last_error();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aetheris_send_transaction(string toAddress, double amount);

        public static void Initialize() => aetheris_init();
        
        public static int StartNode(ushort port, string dbPath) => aetheris_start_node(port, dbPath);
        
        public static bool IsWalletInitialized() => aetheris_is_initialized();
        
        public static bool CreateWallet() => aetheris_create_wallet();
        
        public static bool ImportWallet(string mnemonic) => aetheris_import_wallet(mnemonic);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aetheris_start_mining();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aetheris_stop_mining();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aetheris_is_mining();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aetheris_connect_peer(string address);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint aetheris_get_peer_count();

        public static bool StartMining() => aetheris_start_mining();
        public static bool StopMining() => aetheris_stop_mining();
        public static bool IsMining() => aetheris_is_mining();
        public static bool ConnectPeer(string address) => aetheris_connect_peer(address);
        public static uint GetPeerCount() => aetheris_get_peer_count();

        public static string GetGenesisPhrase()
        {
            var ptr = aetheris_get_genesis_phrase();
            if (ptr == IntPtr.Zero) return "";
            try {
                return Marshal.PtrToStringAnsi(ptr) ?? "";
            } finally {
                aetheris_free_string(ptr);
            }
        }

        public static string GetLastError()
        {
            var ptr = aetheris_get_last_error();
            if (ptr == IntPtr.Zero) return "";
            return Marshal.PtrToStringAnsi(ptr) ?? "";
        }

        public static string GetNodeStatus()
        {
            var buffer = aetheris_get_node_status_bin();
            if (buffer.Ptr == IntPtr.Zero) return "{}";
            try
            {
                byte[] data = new byte[(int)buffer.Len];
                Marshal.Copy(buffer.Ptr, data, 0, (int)buffer.Len);
                return Encoding.UTF8.GetString(data);
            }
            finally
            {
                aetheris_free_buffer(buffer);
            }
        }

        public static (bool Success, string Error) SendTransaction(string address, double amount)
        {
            try
            {
                bool success = aetheris_send_transaction(address, amount);
                string error = success ? "" : GetLastError();
                return (success, error);
            }
            catch (Exception ex)
            {
                return (false, ex.Message);
            }
        }
    }
}
