using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Threading.Tasks;
using Aetheris.App.Core;
using System.Text.Json;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Collections.ObjectModel;

namespace Aetheris.App
{
    public class NotificationItem
    {
        public string Title { get; set; } = "";
        public string Message { get; set; } = "";
        public Brush Color { get; set; } = Brushes.Gray;
    }

    public partial class MainWindow : Window
    {
        private DispatcherTimer _updateTimer;
        private ObservableCollection<NotificationItem> _notifications = new ObservableCollection<NotificationItem>();
        private static System.Threading.Mutex? _singleInstanceMutex;

        private string _currentVaultPath = "";

        public MainWindow()
        {
            if (!EnsureSingleInstance())
            {
                Application.Current.Shutdown();
                return;
            }

            InitializeComponent();
            NotificationContainer.ItemsSource = _notifications;
            
            try 
            {
                // Initialize Rust Backend
                AetherisBackend.Initialize();
                
                // Ensure DB is in the same directory as the executable
                string exePath = System.IO.Path.GetDirectoryName(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName) ?? ".";
                _currentVaultPath = System.IO.Path.Combine(exePath, "aetheris_vault_v2");
                Log($"Kernel target DB path: {_currentVaultPath}");
                
                // Start node - this will open the DB
                int result = AetherisBackend.StartNode(10001, _currentVaultPath);
                if (result != 0)
                {
                    Log($"Kernel Start Failed: {AetherisBackend.GetLastError()}");
                }

                bool isInitialized = AetherisBackend.IsWalletInitialized();
                Log($"Kernel check: Wallet initialized = {isInitialized}");

                UpdateWalletState();

                if (!isInitialized)
                {
                    Log("No wallet detected. Prompting for initialization...");
                    // Use Dispatcher to ensure the wizard shows after the main window is ready
                    Dispatcher.BeginInvoke(new Action(() => {
                        ShowSetupWizard();
                    }), DispatcherPriority.Loaded);
                }
                else
                {
                    Log("Wallet detected and loaded successfully.");
                }
                
                Log("Kernel initialized successfully.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Kernel Critical Error: {ex.Message}\n\nThis usually happens if another instance is running or the database is corrupted.", "Aetheris Fatal Error", MessageBoxButton.OK, MessageBoxImage.Error);
                Log($"Kernel Error: {ex.Message}");
            }

            // Setup UI Update Timer
            _updateTimer = new DispatcherTimer();
            _updateTimer.Interval = TimeSpan.FromSeconds(2);
            _updateTimer.Tick += UpdateTimer_Tick;
            _updateTimer.Start();
        }

        private bool EnsureSingleInstance()
        {
            bool createdNew;
            _singleInstanceMutex = new System.Threading.Mutex(true, "Aetheris_Unique_Application_ID", out createdNew);
            if (!createdNew)
            {
                MessageBox.Show("Another instance of Aetheris is already running. Please close it first.", "Aetheris", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            return true;
        }

        private void BtnSwitchVault_Click(object sender, RoutedEventArgs e)
        {
            string vaultName = TxtVaultName.Text.Trim();
            if (string.IsNullOrEmpty(vaultName)) return;

            // Simple sanitation: only allow alphanumeric and underscores
            if (!System.Text.RegularExpressions.Regex.IsMatch(vaultName, @"^[a-zA-Z0-9_]+$"))
            {
                MessageBox.Show("Vault name must be alphanumeric.", "Aetheris", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string exePath = System.IO.Path.GetDirectoryName(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName);
            string newVaultPath = System.IO.Path.Combine(exePath, vaultName);

            if (newVaultPath == _currentVaultPath)
            {
                ShowNotification("Info", "Already using this vault.", Brushes.SkyBlue);
                return;
            }

            try 
            {
                Log($"Switching to vault: {newVaultPath}");
                AetherisBackend.StartNode(10001, newVaultPath);
                _currentVaultPath = newVaultPath;
                ActiveVaultPathText.Text = _currentVaultPath;

                UpdateWalletState();

                if (!AetherisBackend.IsWalletInitialized())
                {
                    ShowNotification("New Vault", "This vault is empty. Please initialize it.", Brushes.Orange);
                    ShowSetupWizard();
                }
                else
                {
                    ShowNotification("Success", "Vault switched successfully.", Brushes.Green);
                }
            }
            catch (Exception ex)
            {
                Log($"Switch Error: {ex.Message}");
            }
        }

        private void UpdateWalletState()
        {
            bool isInitialized = AetherisBackend.IsWalletInitialized();
            Log($"Updating UI State: Wallet initialized = {isInitialized}");

            if (isInitialized)
            {
                NoWalletOverlay.Visibility = Visibility.Collapsed;
                MainContentArea.IsEnabled = true;
                
                // Trigger an immediate update of node status to refresh address and balance
                UpdateTimer_Tick(null, null);
            }
            else
            {
                NoWalletOverlay.Visibility = Visibility.Visible;
                // Clear UI values
                if (BalanceText != null) BalanceText.Text = "0.00 AET";
                if (WalletAddressText != null) WalletAddressText.Text = "Not Initialized";
            }
        }

        private void BtnInitializeFromOverlay_Click(object sender, RoutedEventArgs e)
        {
            ShowSetupWizard();
            UpdateWalletState();
        }

        private void ShowSetupWizard()
        {
            // Simple visual blocking of the main UI until initialized
            MainContentArea.IsEnabled = false;
            
            var result = MessageBox.Show(
                "Welcome to Aetheris! No wallet found.\n\n" +
                "Click YES to create a new wallet.\n" +
                "Click NO to import the Genesis Developer Wallet.", 
                "Aetheris Setup Wizard", 
                MessageBoxButton.YesNoCancel, 
                MessageBoxImage.Information);

            if (result == MessageBoxResult.Yes)
            {
                if (AetherisBackend.CreateWallet())
                {
                    UpdateWalletState();
                    ShowNotification("Success", "New shielded wallet created.", Brushes.Green);
                    Log("New wallet initialized.");
                }
            }
            else if (result == MessageBoxResult.No)
            {
                string genesis = AetherisBackend.GetGenesisPhrase();
                if (AetherisBackend.ImportWallet(genesis))
                {
                    UpdateWalletState();
                    ShowNotification("Genesis Imported", "Genesis allocation claimed successfully!", Brushes.Gold);
                    Log("Genesis wallet imported. Assets allocated.");
                }
            }
            else
            {
                Log("Wallet creation skipped. Application will be in read-only mode.");
            }
        }

        private void UpdateTimer_Tick(object? sender, EventArgs e)
        {
            try 
            {
                string jsonStatus = AetherisBackend.GetNodeStatus();
                if (string.IsNullOrEmpty(jsonStatus) || jsonStatus == "{}") return;

                using var doc = JsonDocument.Parse(jsonStatus);
                var status = doc.RootElement;

                if (status.TryGetProperty("peers", out var peersProp))
                    PeersText.Text = peersProp.GetInt32().ToString();
                
                if (status.TryGetProperty("height", out var heightProp))
                    HeightText.Text = heightProp.GetInt32().ToString();

                if (status.TryGetProperty("version", out var versionProp))
                    VersionText.Text = versionProp.GetString();

                if (status.TryGetProperty("privacy_score", out var scoreProp))
                    PrivacyScoreText.Text = $"{scoreProp.GetInt32()}%";

                if (status.TryGetProperty("address", out var addrProp))
                    WalletAddressText.Text = addrProp.GetString();

                if (status.TryGetProperty("anonymity_set", out var anonProp))
                    AnonymitySetText.Text = $"{anonProp.GetInt32():N0} Notes";

                if (status.TryGetProperty("balance_atoms", out var balanceProp))
                {
                    double balance = balanceProp.ValueKind == JsonValueKind.Number 
                        ? balanceProp.GetDouble() / 100000000.0 
                        : double.Parse(balanceProp.GetString() ?? "0") / 100000000.0;
                    
                    string balanceStr = $"{balance:N2} AET";
                    BalanceText.Text = balanceStr;
                    WalletAetBalance.Text = balanceStr;
                }

                if (status.TryGetProperty("transactions", out var txsProp) && txsProp.ValueKind == JsonValueKind.Array)
                {
                    UpdateTransactionList(txsProp);
                }
                
                if (status.TryGetProperty("status", out var statusProp))
                {
                    string? nodeStatus = statusProp.GetString();
                    bool isActive = nodeStatus == "Active";
                    string newStatus = isActive ? "Connected" : "Offline";
                    
                    if (BottomStatusText.Text != newStatus)
                    {
                        var color = isActive ? Brushes.Green : Brushes.Red;
                        ShowNotification("Network Status", $"Node is now {newStatus}", color);
                    }

                    BottomStatusText.Text = newStatus;
                }
            }
            catch (Exception ex)
            {
                // Only log if it's a real error, not just initialization lag
                if (LogText != null)
                {
                    Log($"Update Error: {ex.Message}");
                }
            }
        }

        private void BtnRevealMnemonic_Click(object sender, RoutedEventArgs e)
        {
            ShowNotification("Security", "Mnemonic export is only available in administrative mode.", Brushes.Orange);
        }

        private void BtnSendTransaction_Click(object sender, RoutedEventArgs e)
        {
            BtnNewTransaction_Click(sender, e);
        }

        private void BtnCopyAddress_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(WalletAddressText.Text) && WalletAddressText.Text != "Generating...")
            {
                Clipboard.SetText(WalletAddressText.Text);
                ShowNotification("Address Copied", "Shielded address copied to clipboard.", Brushes.Green);
            }
        }

        private void Nav_Click(object sender, RoutedEventArgs e)
        {
            var btn = sender as Button;
            if (btn == null) return;

            // Reset all buttons
            foreach (var child in ((StackPanel)btn.Parent).Children)
            {
                if (child is Button b) b.Tag = null;
            }
            btn.Tag = "Active";

            // Hide all panels
            OverviewPanel.Visibility = Visibility.Collapsed;
            WalletPanel.Visibility = Visibility.Collapsed;
            SettingsPanel.Visibility = Visibility.Collapsed;
            NodePanel.Visibility = Visibility.Collapsed;
            MixnetPanel.Visibility = Visibility.Collapsed;
            VaultPanel.Visibility = Visibility.Collapsed;

            // Show selected panel
            switch (btn.Content.ToString())
            {
                case "Overview":
                    OverviewPanel.Visibility = Visibility.Visible;
                    break;
                case "Shielded Wallet":
                    WalletPanel.Visibility = Visibility.Visible;
                    break;
                case "Switch Vault":
                    VaultPanel.Visibility = Visibility.Visible;
                    ActiveVaultPathText.Text = _currentVaultPath;
                    break;
                case "Node Status":
                    NodePanel.Visibility = Visibility.Visible;
                    break;
                case "Mixnet Privacy":
                    MixnetPanel.Visibility = Visibility.Visible;
                    break;
                case "Settings":
                    SettingsPanel.Visibility = Visibility.Visible;
                    break;
            }
        }

        private void BtnNewTransaction_Click(object sender, RoutedEventArgs e)
        {
            TransactionModal.Visibility = Visibility.Visible;
            TxtRecipient.Text = "";
            TxtAmount.Text = "";
        }

        private void BtnCancelTx_Click(object sender, RoutedEventArgs e)
        {
            TransactionModal.Visibility = Visibility.Collapsed;
            ResetTxModal();
        }

        private void ResetTxModal()
        {
            TxActionGrid.Visibility = Visibility.Visible;
            TxStatusPanel.Visibility = Visibility.Collapsed;
            BtnConfirmTx.IsEnabled = true;
            TxStatusText.Text = "Generating ZK-SNARK Proof...";
        }

        private async void BtnConfirmTx_Click(object sender, RoutedEventArgs e)
        {
            string address = TxtRecipient.Text;
            if (string.IsNullOrWhiteSpace(address))
            {
                MessageBox.Show("Please enter a valid recipient address.", "Aetheris", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!double.TryParse(TxtAmount.Text, out double amount) || amount <= 0)
            {
                MessageBox.Show("Please enter a valid amount.", "Aetheris", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Show progress
            TxActionGrid.Visibility = Visibility.Collapsed;
            TxStatusPanel.Visibility = Visibility.Visible;
            
            try 
            {
                // Simulate ZK Proof Generation (Halo2)
                TxStatusText.Text = "Constructing Value Conservation Circuit...";
                await Task.Delay(800);
                
                TxStatusText.Text = "Synthesizing Halo2 Proof (Bn256)...";
                await Task.Delay(1200);

                TxStatusText.Text = "Broadcasting Shielded Transaction...";
                var (success, error) = AetherisBackend.SendTransaction(address, amount);
                await Task.Delay(500);

                if (success)
                {
                    Log($"Transaction Dispatched: {amount} AET to {address.Substring(0, Math.Min(10, address.Length))}...");
                    ShowNotification("Transaction Sent", $"Successfully dispatched {amount} AET to shielded network.", Brushes.Green);
                    TransactionModal.Visibility = Visibility.Collapsed;
                    ResetTxModal();
                }
                else
                {
                    string errorMsg = string.IsNullOrEmpty(error) ? "The transaction could not be completed." : error;
                    ShowNotification("Transaction Failed", errorMsg, Brushes.Red);
                    MessageBox.Show($"Transaction failed: {errorMsg}", "Aetheris Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    ResetTxModal();
                    TxActionGrid.Visibility = Visibility.Visible;
                    TxStatusPanel.Visibility = Visibility.Collapsed;
                }
            }
            catch (Exception ex)
            {
                Log($"Tx Error: {ex.Message}");
                ResetTxModal();
            }
        }

        private void Log(string message)
        {
            if (LogText == null) return;
            LogText.Text += $"\n[{DateTime.Now:HH:mm:ss}] {message}";
            LogScrollViewer?.ScrollToEnd();
        }

        private async void ShowNotification(string title, string message, Brush color)
        {
            var item = new NotificationItem { Title = title, Message = message, Color = color };
            _notifications.Add(item);
            await Task.Delay(5000);
            _notifications.Remove(item);
        }

        private void UpdateTransactionList(JsonElement transactions)
        {
            if (TransactionList == null) return;

            // Simple check to avoid redrawing if nothing changed
            if (transactions.GetArrayLength() == TransactionList.Items.Count) return;

            TransactionList.Items.Clear();
            foreach (var tx in transactions.EnumerateArray())
            {
                string type = tx.GetProperty("type").GetString() ?? "Unknown";
                double amount = tx.TryGetProperty("amount_atoms", out var atomProp) 
                    ? (atomProp.ValueKind == JsonValueKind.Number ? atomProp.GetDouble() : double.Parse(atomProp.GetString() ?? "0")) / 100000000.0
                    : tx.GetProperty("amount").GetDouble();

                string color = amount < 0 ? "#FF4B4B" : "#00FF41";
                string prefix = amount < 0 ? "" : "+";

                var grid = new Grid { Width = 500 };
                grid.Children.Add(new Ellipse { Width = 30, Height = 30, Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1E1E1E")), HorizontalAlignment = HorizontalAlignment.Left });
                grid.Children.Add(new TextBlock { Text = type, Foreground = Brushes.White, Margin = new Thickness(45, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center });
                grid.Children.Add(new TextBlock { Text = $"{prefix}{amount:N2} AET", Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color)), HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center });

                TransactionList.Items.Add(new ListBoxItem { Content = grid, Background = Brushes.Transparent, Margin = new Thickness(0, 0, 0, 10) });
            }
        }
    }
}
