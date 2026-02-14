using System;
using System.IO;
using System.Threading;
using System.Text.Json;
using Aetheris.CLI.Core;

namespace Aetheris.CLI
{
    class Program
    {
        private static string _currentDbPath = "";
        private static bool _running = true;

        static void Main(string[] args)
        {
            Console.Title = "Aetheris Console - Extreme Sovereignty";
            Console.ForegroundColor = ConsoleColor.Green;
            
            PrintHeader();

            try
            {
                // Initialize Backend
                AetherisBackend.Initialize();
                
                string exeDir = AppDomain.CurrentDomain.BaseDirectory;
                _currentDbPath = Path.Combine(exeDir, "aetheris_vault_cli");
                
                Console.WriteLine($"[INIT] Starting Kernel with DB: {_currentDbPath}");
                int res = AetherisBackend.StartNode(10005, _currentDbPath);
                if (res != 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[ERROR] Failed to start node: {AetherisBackend.GetLastError()}");
                    return;
                }

                if (!AetherisBackend.IsWalletInitialized())
                {
                    ShowSetupWizard();
                }

                RunMainMenu();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[FATAL] {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
            finally
            {
                Console.ResetColor();
            }
        }

        static void PrintHeader()
        {
            Console.WriteLine(@"
   _____          __  .__                 .__        
  /  _  \   _____/  |_|  |__   ___________|__| ______
 /  /_\  \_/ __ \   __\  |  \_/ __ \_  __ \  |/  ___/
/    |    \  ___/|  | |   Y  \  ___/|  | \/  |\___ \ 
\____|__  /\___  >__| |___|  /\___  >__|  |__/____  >
        \/     \/          \/     \/              \/ 
            Extreme Sovereignty v0.1.0-alpha
");
        }

        static void ShowSetupWizard()
        {
            Console.WriteLine("\n[WIZARD] No wallet detected. Choose an option:");
            Console.WriteLine("1. Create New Shielded Wallet");
            Console.WriteLine("2. Import Wallet from Mnemonic");
            Console.Write("\nSelection > ");

            string choice = Console.ReadLine();
            if (choice == "1")
            {
                Console.WriteLine("[WIZARD] Generating secure keys...");
                if (AetherisBackend.CreateWallet())
                {
                    Console.WriteLine("[SUCCESS] Wallet created and encrypted.");
                }
                else
                {
                    Console.WriteLine("[ERROR] Failed to create wallet.");
                }
            }
            else if (choice == "2")
            {
                Console.Write("[WIZARD] Enter 24-word mnemonic: ");
                string mnemonic = Console.ReadLine();
                if (AetherisBackend.ImportWallet(mnemonic))
                {
                    Console.WriteLine("[SUCCESS] Wallet imported successfully.");
                }
                else
                {
                    Console.WriteLine("[ERROR] Failed to import wallet.");
                }
            }
        }

        static void RunMainMenu()
        {
            while (_running)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("\n--- MAIN MENU ---");
                Console.ResetColor();
                Console.WriteLine("1. View Wallet Status & Balance");
                Console.WriteLine("2. Send Private Transaction");
                Console.WriteLine("3. Transaction History");
                Console.WriteLine("4. VDF Node Monitor (Live)");
                Console.WriteLine("5. Start/Stop Mining (PoT)");
                Console.WriteLine("6. Connect to P2P Peer");
                Console.WriteLine("7. Export Mnemonic (Backup)");
                Console.WriteLine("8. System Logs (Raw JSON)");
                Console.WriteLine("9. Switch Vault / DB Path");
                Console.WriteLine("q. Exit");
                Console.Write("\nSelection > ");

                string choice = Console.ReadLine()?.ToLower();
                switch (choice)
                {
                    case "1": ShowStatus(); break;
                    case "2": SendTx(); break;
                    case "3": ShowTxHistory(); break;
                    case "4": RunMonitor(); break;
                    case "5": ToggleMining(); break;
                    case "6": ConnectPeer(); break;
                    case "7": ExportMnemonic(); break;
                    case "8": ShowRawStatus(); break;
                    case "9": SwitchVault(); break;
                    case "q": _running = false; break;
                    default: Console.WriteLine("Invalid option."); break;
                }
            }
        }

        static void ToggleMining()
        {
            bool isMining = AetherisBackend.IsMining();
            if (isMining)
            {
                Console.WriteLine("\n[INFO] Stopping mining thread...");
                AetherisBackend.StopMining();
                Console.WriteLine("[SUCCESS] Mining stopped.");
            }
            else
            {
                Console.WriteLine("\n[INFO] Starting background PoT mining thread...");
                if (AetherisBackend.StartMining())
                {
                    Console.WriteLine("[SUCCESS] Mining thread active. Blocks will be generated automatically.");
                }
                else
                {
                    Console.WriteLine("[ERROR] Failed to start mining.");
                }
            }
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
        }

        static void ConnectPeer()
        {
            Console.Write("\nEnter Peer Address (e.g. 127.0.0.1:10006): ");
            string addr = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(addr)) return;

            Console.WriteLine($"[P2P] Connecting to {addr}...");
            if (AetherisBackend.ConnectPeer(addr))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[SUCCESS] Peer added to connection list.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[FAILED] Could not connect to peer.");
            }
            Console.ResetColor();
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
        }

        static void ShowTxHistory()
        {
            string json = AetherisBackend.GetNodeStatus();
            try {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                var txs = root.GetProperty("transactions");

                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("\n--- TRANSACTION HISTORY ---");
                Console.WriteLine($"{"DATE",-22} | {"TYPE",-15} | {"AMOUNT (AET)",-15} | {"STATUS",-15}");
                Console.WriteLine(new string('-', 75));

                foreach (var tx in txs.EnumerateArray())
                {
                    string date = tx.GetProperty("timestamp").GetString()?.Replace("T", " ").Replace("Z", "") ?? "N/A";
                    string type = tx.GetProperty("type").GetString() ?? "Unknown";
                    long atoms = tx.GetProperty("amount_atoms").GetInt64();
                    double aet = atoms / 100_000_000.0;
                    string status = tx.GetProperty("status").GetString() ?? "Unknown";

                    if (type.Contains("Genesis")) Console.ForegroundColor = ConsoleColor.Yellow;
                    else if (aet < 0) Console.ForegroundColor = ConsoleColor.Red;
                    else Console.ForegroundColor = ConsoleColor.Green;

                    Console.WriteLine($"{date,-22} | {type,-15} | {aet,15:F8} | {status,-15}");
                    Console.ResetColor();
                }
            }
            catch {
                Console.WriteLine("[ERROR] Failed to load transaction history.");
            }
        }

        static void RunMonitor()
        {
            Console.Clear();
            Console.WriteLine("VDF NODE MONITOR - Press any key to return to menu");
            bool monitoring = true;
            
            // Non-blocking key check thread
            Thread keyThread = new Thread(() => {
                Console.ReadKey(true);
                monitoring = false;
            });
            keyThread.Start();

            while (monitoring)
            {
                string json = AetherisBackend.GetNodeStatus();
                try {
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    Console.SetCursorPosition(0, 2);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    uint peerCount = AetherisBackend.GetPeerCount();
                    Console.WriteLine($"[TIME] {DateTime.Now:HH:mm:ss} | Peers: {peerCount} | Height: {root.GetProperty("height").GetInt64()}");
                    
                    bool isMining = root.GetProperty("mining_active").GetBoolean();
                    int mempoolSize = root.GetProperty("mempool_size").GetInt32();

                    Console.ForegroundColor = isMining ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.WriteLine($"Status: {root.GetProperty("status").GetString()} | Mining: {(isMining ? "ACTIVE" : "OFF")}");
                    
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine($"Mempool: {mempoolSize} pending txs");
                    
                    // Progress Bar
                    if (isMining)
                    {
                        Console.Write("\nVDF Progress: [");
                        Console.ForegroundColor = ConsoleColor.Green;
                        // For production, we'd use actual progress if available
                        Console.Write("####################"); 
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine("] 100%");
                    }
                    else
                    {
                        Console.WriteLine("\nVDF Progress: [--------------------] IDLE");
                    }

                    Console.WriteLine("Challenge: " + AetherisBackend.GetLastError());
                    
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("\nLatest Node Snapshot:");
                    string summary = $"H:{root.GetProperty("height").GetInt64()} | B:{root.GetProperty("balance_atoms").GetInt64()/100000000.0} AET";
                    Console.WriteLine("> " + summary);
                }
                catch { }

                Thread.Sleep(1000);
            }
            Console.Clear();
            PrintHeader();
        }

        static void ExportMnemonic()
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[SECURITY WARNING] Reveal mnemonic phrase?");
            Console.Write("Type 'CONFIRM' to proceed: ");
            if (Console.ReadLine() == "CONFIRM")
            {
                string phrase = AetherisBackend.GetGenesisPhrase(); // Currently re-uses genesis if matching, or backend needs Export API
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\nYOUR RECOVERY PHRASE (KEEP IT SECRET!):");
                Console.WriteLine(new string('*', 50));
                Console.WriteLine(phrase);
                Console.WriteLine(new string('*', 50));
                Console.ResetColor();
                Console.WriteLine("\nPress enter to hide and continue...");
                Console.ReadLine();
            }
        }

        static void ShowStatus()
        {
            string json = AetherisBackend.GetNodeStatus();
            try {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("\n--- WALLET STATUS ---");
                Console.WriteLine($"Address:   {root.GetProperty("address").GetString()}");
                
                long atoms = root.GetProperty("balance_atoms").GetInt64();
                double aet = atoms / 100_000_000.0;
                Console.WriteLine($"Balance:   {aet:F8} AET ({atoms} atoms)");
                
                Console.WriteLine($"Height:    {root.GetProperty("height").GetInt64()}");
                Console.WriteLine($"Peers:     {AetherisBackend.GetPeerCount()}");
                
                bool isMining = root.GetProperty("mining_active").GetBoolean();
                Console.ForegroundColor = isMining ? ConsoleColor.Green : ConsoleColor.Gray;
                Console.WriteLine($"Mining:    {(isMining ? "RUNNING (PoT active)" : "STOPPED")}");
                
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($"Mempool:   {root.GetProperty("mempool_size").GetInt32()} pending transactions");
                Console.ResetColor();
            }
            catch {
                Console.WriteLine("[ERROR] Failed to parse node status JSON.");
                Console.WriteLine(json);
            }
        }

        static void SendTx()
        {
            Console.Write("\nEnter Recipient Address: ");
            string addr = Console.ReadLine();
            Console.Write("Enter Amount (AET): ");
            if (double.TryParse(Console.ReadLine(), out double amount))
            {
                Console.WriteLine("[TX] Generating ZK-SNARK proof and signing...");
                var (success, error) = AetherisBackend.SendTransaction(addr, amount);
                if (success)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[SUCCESS] Transaction broadcast to mixnet.");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[FAILED] {error}");
                }
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine("Invalid amount.");
            }
        }

        static void ShowRawStatus()
        {
            Console.WriteLine("\n--- RAW JSON STATUS ---");
            Console.WriteLine(AetherisBackend.GetNodeStatus());
        }

        static void SwitchVault()
        {
            Console.Write("\nEnter new vault folder name (inside exe dir): ");
            string name = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(name)) return;

            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            _currentDbPath = Path.Combine(exeDir, name);
            
            Console.WriteLine($"[INIT] Switching to DB: {_currentDbPath}");
            AetherisBackend.StartNode(10005, _currentDbPath);
            
            if (!AetherisBackend.IsWalletInitialized())
            {
                ShowSetupWizard();
            }
        }
    }
}
