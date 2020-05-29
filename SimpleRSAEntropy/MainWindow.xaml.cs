using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;
using System.Numerics;

namespace SimpleRSA
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        RSA rsa = new RSA();
        public MainWindow()
        {
            InitializeComponent();

            initializeMainTextBlock();

            rsa.KeyGenerated += Rsa_KeyGenerated;
            rsa.MessageEncrypted += Rsa_MessageEncrypted;
        }

        private void Rsa_MessageEncrypted(object sender, EventArgs e)
        {
            messageEncryptedInfoBlock.Text = "yes";
            messageEncryptedInfoBlock.Foreground = Brushes.Green;
            decryptButton.Visibility = Visibility.Visible;
        }

        private void Rsa_KeyGenerated(object sender, EventArgs e)
        {
            keyGeneratedInfoBlock.Text = "yes";
            keyGeneratedInfoBlock.Foreground = Brushes.Green;
            loadButton.Visibility = Visibility.Visible;
        }

        string inputText;

        //open a text file and make the encryptButton visible
        private void loadButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.InitialDirectory = AppDomain.CurrentDomain.BaseDirectory;
            dialog.Filter = "text files (*.txt)|*.txt";

            if (dialog.ShowDialog() == true) //nullable bool
            {
                using (StreamReader reader = File.OpenText(dialog.FileName))
                {
                    inputText = reader.ReadToEnd();
                    mainTextBlock.Text += "Message: " + inputText + Environment.NewLine;

                    encryptButton.Visibility = Visibility.Visible;
                }
            }
        }

        //encrypt the inputText and save ciphertext as a hexadecimal number
        private void encryptButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                rsa.Encrypt(inputText);

                SaveFileDialog dialog = new SaveFileDialog();
                dialog.InitialDirectory = AppDomain.CurrentDomain.BaseDirectory;
                dialog.Filter = "text files (*.txt)|*.txt";
                dialog.FileName = "ciphertext";

                if (dialog.ShowDialog() == true)
                {
                    using (StreamWriter writer = new StreamWriter(dialog.FileName))
                    {
                        writer.WriteLine("Ciphertext as a hexadecimal number:");
                        writer.WriteLine(rsa.Ciphertext.ToString("x"));
                    }
                }
            }
            catch(EncryptionException ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }

        }

        //decrypt the ciphertext and write the text to a file and closes the app
        private void decryptButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                rsa.Decrypt(rsa.Ciphertext);

                SaveFileDialog dialog = new SaveFileDialog();
                dialog.InitialDirectory = AppDomain.CurrentDomain.BaseDirectory;
                dialog.Filter = "text files (*.txt)|*.txt";
                dialog.FileName = "output";

                if (dialog.ShowDialog() == true)
                {
                    using (StreamWriter writer = new StreamWriter(dialog.FileName))
                    {
                        writer.WriteLine(rsa.DecryptedCiphertext);
                        this.Close();
                    }
                }
            }
            catch (EncryptionException ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        //MessageBox shown when key is being counted
        private void generateKeyButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("Press OK to generate a key. This may take up to 20 seconds. " +
                "Please wait patiently. When the key will be generated " +  
                "you will see green yes near the 'Key generated' " +
                "text", "Please wait patiently", MessageBoxButton.OK);
            rsa.GenerateKey();
        }
        
        //fills the main textBlock with instructions on how to use the application
        private void initializeMainTextBlock()
        {
            mainTextBlock.Text = "This program is a simple implementation of the RSA algorithm." +
                Environment.NewLine + "1. Click on the button to generate a key. This may take " +
                "some time. Other button are invisible now." + Environment.NewLine +
                "2. Click on the load button and choose a text file. There should already be " +
                "\"input.txt\" file in the folder to easily test the app." + Environment.NewLine +
                "3. Click on the encrypt button to begin encryption. Then either choose a text file to " +
                "save the ciphertext or just click on the save button." + Environment.NewLine +
                "4. Now you can click on the decrypt button to check if encryption is correct. " +
                "Similarly to the previous step, now you can save the text in a file." + Environment.NewLine;
        }
    }
}
