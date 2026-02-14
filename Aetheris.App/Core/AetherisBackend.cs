using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;

namespace Aetheris.App.Core
{
    public class AetherisBackend
    {
        private const string LibName = "aetheris_ffi";

        // Shared Bridge Key (Must match Rust side exactly)
        private static readonly byte[] BridgeKey = Encoding.ASCII.GetBytes("AETHERIS_SECURE_BRIDGE_2026_KEY!");

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
        public static extern BinaryBuffer aetheris_execute_command_bin(BinaryBuffer command);

        public static string GetNodeStatus()
        {
            var buffer = aetheris_get_node_status_bin();
            return DecryptBuffer(buffer);
        }

        public static string ExecuteCommandBinary(string jsonCommand)
        {
            var inputBuffer = EncryptString(jsonCommand);
            try
            {
                var outputBuffer = aetheris_execute_command_bin(inputBuffer);
                return DecryptBuffer(outputBuffer);
            }
            finally
            {
                // We must free the input buffer if it was allocated in a way that needs freeing.
                // Since EncryptString uses Marshal.AllocHGlobal, we free it here.
                if (inputBuffer.Ptr != IntPtr.Zero) Marshal.FreeHGlobal(inputBuffer.Ptr);
            }
        }

        private static BinaryBuffer EncryptString(string plainText)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);

            int tagSize = 16;
            byte[] ciphertext = new byte[plainBytes.Length];
            byte[] tag = new byte[tagSize];

            using (var aes = new AesGcm(BridgeKey))
            {
                aes.Encrypt(nonce, plainBytes, ciphertext, tag);
            }

            // Protocol: [12 bytes Nonce] + [Ciphertext] + [16 bytes Tag]
            byte[] finalPayload = new byte[12 + ciphertext.Length + tagSize];
            Array.Copy(nonce, 0, finalPayload, 0, 12);
            Array.Copy(ciphertext, 0, finalPayload, 12, ciphertext.Length);
            Array.Copy(tag, 0, finalPayload, 12 + ciphertext.Length, tagSize);

            IntPtr ptr = Marshal.AllocHGlobal(finalPayload.Length);
            Marshal.Copy(finalPayload, 0, ptr, finalPayload.Length);

            return new BinaryBuffer { Ptr = ptr, Len = (UIntPtr)finalPayload.Length };
        }

        private static string DecryptBuffer(BinaryBuffer buffer)
        {
            if (buffer.Ptr == IntPtr.Zero || (int)buffer.Len == 0) return "{}";

            try
            {
                byte[] data = new byte[(int)buffer.Len];
                Marshal.Copy(buffer.Ptr, data, 0, data.Length);

                // Protocol: [12 bytes Nonce] + [Ciphertext] + [16 bytes Tag]
                if (data.Length < 12 + 16) return "{\"error\": \"Invalid encrypted buffer (too short)\"}";

                byte[] nonce = new byte[12];
                Array.Copy(data, 0, nonce, 0, 12);

                int tagSize = 16;
                int ciphertextLen = data.Length - 12 - tagSize;
                
                byte[] ciphertext = new byte[ciphertextLen];
                byte[] tag = new byte[tagSize];
                
                Array.Copy(data, 12, ciphertext, 0, ciphertextLen);
                Array.Copy(data, 12 + ciphertextLen, tag, 0, tagSize);

                byte[] decrypted = new byte[ciphertextLen];
                using (var aes = new AesGcm(BridgeKey))
                {
                    aes.Decrypt(nonce, ciphertext, tag, decrypted);
                }

                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception ex)
            {
                return $"{{\"error\": \"Decryption failed: {ex.Message}\"}}";
            }
            finally
            {
                aetheris_free_buffer(buffer);
            }
        }

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

        public static bool IsWalletInitialized() => aetheris_is_initialized();
        public static bool CreateWallet() => aetheris_create_wallet();
        public static bool ImportWallet(string mnemonic) => aetheris_import_wallet(mnemonic);

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

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr aetheris_get_last_error();

        public static string GetLastError()
        {
            var ptr = aetheris_get_last_error();
            if (ptr == IntPtr.Zero) return "";
            return Marshal.PtrToStringAnsi(ptr) ?? "";
        }

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr aetheris_get_vdf_challenge();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr aetheris_solve_vdf_local();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aetheris_submit_vdf_proof(string result, string proof);

        public static string GetVdfChallenge()
        {
            var ptr = aetheris_get_vdf_challenge();
            return ptr == IntPtr.Zero ? "" : Marshal.PtrToStringAnsi(ptr) ?? "";
        }

        public static string SolveVdfLocal()
        {
            var ptr = aetheris_solve_vdf_local();
            return ptr == IntPtr.Zero ? "" : Marshal.PtrToStringAnsi(ptr) ?? "";
        }

        public static bool SubmitVdfProof(string result, string proof)
        {
            return aetheris_submit_vdf_proof(result, proof);
        }

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr aetheris_execute_command(string commandJson);

        public static string ExecuteCommand(string command)
        {
            var ptr = aetheris_execute_command(command);
            if (ptr == IntPtr.Zero) return "{\"error\": \"Null result\"}";
            try {
                return Marshal.PtrToStringAnsi(ptr) ?? "{}";
            } finally {
                aetheris_free_string(ptr);
            }
        }

        public static void Initialize()
        {
            aetheris_init();
        }

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aetheris_send_transaction(string toAddress, double amount);

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

        public static int StartNode(ushort port, string dbPath)
        {
            return aetheris_start_node(port, dbPath);
        }
    }
}
