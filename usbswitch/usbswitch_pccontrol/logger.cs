using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace usbswitch_pccontrol
{
    delegate void AppendLog(string s);

    static class logger
    {
        static AppendLog logDest;

        public static void SetLogDest(AppendLog dest)
        {
            logDest = dest;
        }

        public static void Line(string s)
        {
            logDest(s);
            logDest(Environment.NewLine);
        }
    }
}
