using System;
using System.Collections.Generic;
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



namespace usbswitch_pccontrol
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            logger.SetLogDest( AppendLogToTextbox );
        }

        public void AppendLogToTextbox(string s){
            
            textboxLog.AppendText(s);
            textboxLog.Select(textboxLog.Text.Length, 0);
            textboxLog.ScrollToEnd();
        }

        private void button5V_Click(object sender, RoutedEventArgs e)
        {
            if (button5V.Content.ToString().EndsWith("OFF"))
            {
                serial_io.SendCommand(textboxComPort.Text, "dis5V");
                button5V.Content = "5V ON";
            }
            else
            {
                serial_io.SendCommand(textboxComPort.Text, "ena5V");
                button5V.Content = "5V OFF";
            }
            serial_io.SendCommand(textboxComPort.Text, "q");
        }

        private void button3_3V_Click(object sender, RoutedEventArgs e)
        {
            if (button3_3V.Content.ToString().EndsWith("OFF"))
            {
                serial_io.SendCommand(textboxComPort.Text, "dis3_3V");
                button3_3V.Content = "3.3V ON";
            }
            else
            {
                serial_io.SendCommand(textboxComPort.Text, "ena3_3V");
                button3_3V.Content = "3.3V OFF";
            }
            serial_io.SendCommand(textboxComPort.Text, "q");
        }

        private void buttonUSB_Click(object sender, RoutedEventArgs e)
        {
            if (buttonUSB.Content.ToString().EndsWith("OFF"))
            {
                serial_io.SendCommand(textboxComPort.Text, "disUSB");
                buttonUSB.Content = "USB ON";
            }
            else
            {
                serial_io.SendCommand(textboxComPort.Text, "enaUSB");
                buttonUSB.Content = "USB OFF";
            }
            serial_io.SendCommand(textboxComPort.Text, "q");
        }

        private void buttonConnect_Click(object sender, RoutedEventArgs e)
        {
            serial_io.SendCommand(textboxComPort.Text, "q");
        }

        private void buttonSearch_Click(object sender, RoutedEventArgs e)
        {
            textboxComPort.Text = serial_io.FindPort();   
        }
    }
}
