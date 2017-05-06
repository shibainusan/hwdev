using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO.Ports;

namespace usbswitch_pccontrol
{
    static class serial_io
    {

        static string ReadLine(SerialPort p)
        {
            string ret="";

            if (!p.IsOpen)
            {
                return ret;
            }

            try
            {
                ret = p.ReadLine();
                logger.Line("ReadLine(): " + ret);
            }
            catch(Exception e)
            {
                logger.Line("ReadLine(): " + e.Message);
            }

            return ret;
        }

        static bool WriteLine(SerialPort p, string s)
        {
            bool ret = true;

            if (!p.IsOpen)
            {
                return false;
            }

            logger.Line("WriteLine(): " + s);
            try
            {
                p.WriteLine(s);

            }
            catch (Exception e)
            {
                logger.Line("WriteLine(): " + e.Message);
                ret = false;
            }
            return ret;
        }

        static SerialPort OpenSerial(string port)
        {

            SerialPort p = new SerialPort(port, 9600, Parity.None, 8, StopBits.One);
            p.NewLine = "\r\n"; //0x0D 0x0A
            p.ReadTimeout = 300;
            p.WriteTimeout = 300;
            p.DtrEnable = true; //the virtual port requires this to trigger the data retrieval. 
            p.RtsEnable = true;

            try
            {
                p.Open();
            }
            catch (Exception e)
            {
                logger.Line("OpenSerial(): " + e.Message);
            }
            return p;
        }

        public static string FindPort()
        {
            string ret = "";
            string[] ports = SerialPort.GetPortNames();

            foreach (string port in ports)
            {
                try
                {
                    using (SerialPort p = OpenSerial(port))
                    {
                        string s = "Try opening " + port;
                        logger.Line(s);

                        string resp;

                        resp = ReadLine(p);
                        WriteLine(p, "?");
                        resp = ReadLine(p);
                        p.Close();

                        if (resp.StartsWith("[?] OK,"))
                        {
                            ret = port;
                            logger.Line("FindPort(): device detected on " + port);
                            break;
                        }

                    }
                }
                catch (Exception e)
                {
                    logger.Line("FindPort(): " + e.Message);
                }
            }
            return ret;
        }

        public static string SendCommand(string port, string cmd)
        {
            string ret = "";
            try
            {
                using (SerialPort p = OpenSerial(port))
                {
                    WriteLine(p, cmd);
                    ret = ReadLine(p);
                }
            }
            catch (Exception e)
            {
                logger.Line("SendCommand(): " + e.Message);
            }

            return ret;
        }
            
    }
}
