using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Net;
using System.Web.Security;
using Cinchoo.Core.Ini;
using Ionic.Zip;
using System.Net.Sockets;
using System.Security.Permissions;
using System.Diagnostics;
namespace ConsoleApp2
{
   public class Program
    {

        [STAThread]
       public static void Main(string[] args)
        {
            SubmitSample.Submit list = new SubmitSample.Submit();

            System.Net.ServicePointManager.ServerCertificateValidationCallback +=
delegate(object sender, System.Security.Cryptography.X509Certificates.X509Certificate certificate,
                        System.Security.Cryptography.X509Certificates.X509Chain chain,
                        System.Net.Security.SslPolicyErrors sslPolicyErrors)
{
    return true; // **** Always accept all SSL Certt
};

            string Username, Password, SAMPLES;

            using (ChoIniDocument iniDocument = ChoIniDocument.Load(System.Environment.CurrentDirectory + "\\Config\\Config.ini"))
            {
                SAMPLES = iniDocument["CONFIG"]["SAMPLES"];
                Username = iniDocument["CONFIG"]["USER"];
                Password = iniDocument["CONFIG"]["PASSWORD"];
            }

            if (Convert.ToInt32(SAMPLES) <  list.GetSampleList().Length)
            {


                System.IO.StreamWriter writer;
                writer = new StreamWriter(System.Environment.CurrentDirectory + "\\SampleList.txt");
                const string format = "| {0,40} | {1,14} ";
                writer.WriteLine("Malware_FYPJ Console Application");
                writer.WriteLine("----------------------------------------------------------------------------------");
                writer.WriteLine("                        SAMPLES            |                  MD5 ");

                for (int w = 0; w < list.GetSampleList().Length; w++)
                {    
                    writer.WriteLine(string.Format(format, list.GetSampleList()[w].ToString(), list.GetMD5List()[w].ToString()));
                }
                writer.WriteLine("----------------------------------------------------------------------------------");
                writer.WriteLine("Total Samples : " + list.GetSampleList().Length +  "              "  + System.DateTime.Now.ToString());
                string filePath = System.Environment.CurrentDirectory + "\\Config\\Config.ini";
                string[] lines = File.ReadAllLines(System.Environment.CurrentDirectory + "\\Config\\Config.ini");
                for (int i = 0; i < lines.Length; i++)
                {
                    lines[1] = "SAMPLES=" + list.GetSampleList().Length;
                    break;
                }

                File.WriteAllLines(filePath, lines);

                writer.Close();

            }

                /////////////////////////CMD ARUGMENTS /////////////////////////////////////////
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[0] == "-help")
                    {

                        Console.WriteLine("Malware_FYPJ Console Application" + "\n");
                        Console.WriteLine("\n" + "Upload Sample  :   -upload [path]" + "\n" + "Uploading of sample file to our server for analysis," + "\n" + "Example : C:\\Desktop> ConsoleApp.exe -upload C:\\sample.exe" + "\n");
                        Console.WriteLine("Download Sample  :   -download " + "\n" + "Sample file will be downloaded if the MD5 matches your system clipboard," + "\n" + "Example : C:\\Desktop> ConsoleApp.exe -download" + "\n");
                        Console.WriteLine("Download Sample Report  :  -report" + "\n" + "Download of sample's report in the choosen format," + "\n" + "Example : C:\\Desktop> ConsoleApp.exe -report" + "\n");
                        Console.WriteLine("Download Sample Report All Format  :  -reportall" + "\n" + "Download of sample's report in all format," + "\n" + "Example : C:\\Desktop> ConsoleApp.exe -reportall" + "\n");
                    }

                    else if (args[0] == "-report")
                    {
                        try
                        {
                            if (list.AuthenticateUser(Username, Password) == true)
                            {

                                string[] formats = { "html", "json", "maec-1.1.xml", "stix.xml" };

                                Console.WriteLine("Please choose the format you wish to download");

                                for (int a = 0; a < formats.Length; a++)
                                {
                                    Console.WriteLine(a + 1 + "  " + formats[a].ToString());
                                }

                                int choice = Convert.ToInt32(Console.ReadLine());

                                for (int a = 0; a < formats.Length; a++)
                                {
                                    if (a == choice - 1)
                                    {
                                        DownloadReport(formats[a].ToString(), Username, Password);
                                        Console.ReadLine();
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("Incorrect Credentials");
                                break;
                            }

                        }

                        catch (System.IndexOutOfRangeException)
                        {
                            Console.WriteLine("No Credentials entered!");
                        }

                    }

                    else if (args[0] == "-upload")
                    {
                        try
                        {
                            if (list.AuthenticateUser(Username, Password) == true)
                            {
                                Console.WriteLine("Processing");
                                UploadSamples(args[1], list.GetUserGUID(Username), Username);
                                break;
                            }
                            else
                            {
                                Console.WriteLine("Incorrect Credentials");
                                break;
                            }
                        }
                        catch (System.IndexOutOfRangeException)
                        {
                            Console.WriteLine("No Credentials entered!");
                        }

                    }

                    else if (args[0] == "-reportall")
                    {

                        try
                        {
                            if (list.AuthenticateUser(Username, Password) == true)
                            {
                                for (int e = 0; e < list.GetMD5List().Length; e++)
                                {
                                    if (Clipboard.GetText().Contains(list.GetMD5List()[e].ToString()))
                                    {

                                        System.IO.FileStream fs1 = null;
                                        byte[] b1 = null;

                                        b1 = list.DownloadAllReport(list.GetMD5List()[e].ToString());
                                        fs1 = new FileStream(System.Environment.CurrentDirectory + "\\Download\\" + list.GetMD5List()[e].ToString() + "-Reports.zip", FileMode.Create);
                                        fs1.Write(b1, 0, b1.Length);
                                        fs1.Close();
                                        fs1 = null;
                                        Console.WriteLine(list.GetMD5List()[e].ToString() + "-Reports.zip" + "Download finish");
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("Incorrect Credentials");
                            }
                        }
                        catch (System.IndexOutOfRangeException)
                        {
                            Console.WriteLine("No Credentials entered!");
                        }
                    }

                    else if (args[0] == "-download")
                    {

                        try
                        {
                            if (list.AuthenticateUser(Username, Password) == true)
                            {

                                for (int e = 1; e < list.GetMD5List().Length; e++)
                                {
                                    if (Clipboard.GetText().Contains(list.GetMD5List()[e].ToString()))
                                    {

                                        System.IO.FileStream fs1 = null;
                                        byte[] b1 = null;

                                        b1 = list.DownloadSample(list.GetMD5List()[e].ToString(), list.Getfiletype()[e].ToString());
                                        fs1 = new FileStream(System.Environment.CurrentDirectory + "\\Download\\" + list.GetMD5List()[e].ToString() + ".zip", FileMode.Create);
                                        fs1.Write(b1, 0, b1.Length);
                                        fs1.Close();
                                        fs1 = null;
                                        Console.WriteLine(list.GetMD5List()[e].ToString() + ".zip" + "Download finish");
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("Incorrect Credentials");
                            }
                        }
                        catch (System.IndexOutOfRangeException)
                        {
                            Console.WriteLine("No Credentials entered!");
                        }
                    }
                    else { Console.WriteLine("Invalid Command"); }
                }
            }
    


        static public string Getuserinfo()
        {
            Info req = new Info();
            req.Request("http://checkip.dyndns.org");
            string[] a = req.ResponseBody.Split(':');
            string a2 = a[1].Substring(1);
            string[] a3 = a2.Split('<');
            string a4 = a3[0];

            return new WebClient().DownloadString("http://api.hostip.info/get_html.php?ip=" + a4);
        }

        public static string LogInfo(string username, string upload, string download)
        {


            string strHostName = System.Net.Dns.GetHostName();
            //string strIp = System.Net.Dns.GetHostAddresses(strHostName).GetValue(0).ToString();


            string country, ip, city;
            country = "";
            ip = "";
            city = "";

            using (StringReader reader = new StringReader(Getuserinfo()))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.Contains("Country"))
                    {
                        country = line;
                    }
                    if (line.Contains("City"))
                    {
                        city = line;
                    }
                    if (line.Contains("IP"))
                    {
                        ip = line;
                    }

                }
            }


            SubmitSample.Submit log = new SubmitSample.Submit();
   
            log.Getuserinfo(username, strHostName, ip, country, city, DateTime.Now.ToString(), "Console", upload, download);

            return "Success";
        }

        static void DownloadReport(string format, string username, string pw)
        {
            SubmitSample.Submit list = new SubmitSample.Submit();

            try
            {
                if (list.AuthenticateUser(username, pw) == true)
                {

                    for (int e = 0; e < list.GetMD5List().Length; e++)
                    {
                        if (Clipboard.GetText().Contains(list.GetMD5List()[e].ToString()))
                        {

                            System.IO.FileStream fs1 = null;
                            byte[] b1 = null;

                            b1 = list.DownloadReport(list.GetMD5List()[e].ToString(),format);
                            fs1 = new FileStream(System.Environment.CurrentDirectory + "\\Download\\" +list.GetMD5List()[e].ToString()+ "-Report" + ".zip", FileMode.Create);
                            fs1.Write(b1, 0, b1.Length);
                            fs1.Close();
                            fs1 = null;
                            Console.WriteLine(list.GetMD5List()[e].ToString() + ".zip" + "Download finish");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Incorrect Credentials");
                }
            }
            catch (System.IndexOutOfRangeException)
            {
                Console.WriteLine("No Credentials entered!");
            }
        }

        static string UploadSamples(string path, Guid ID,string username)
        {
            Console.WriteLine("Uploading in progress. . . . .");
            string filename = Path.GetFileName(path);
            string filetype = Path.GetExtension(filename);
            StreamReader sourceStream = new StreamReader(path.ToString());
            byte[] fileContents = Encoding.UTF8.GetBytes(sourceStream.ReadToEnd());
            sourceStream.Close();
            SubmitSample.Submit submit = new SubmitSample.Submit();

            Console.WriteLine(submit.SubmitSample(filename, fileContents, ID, filetype));

            LogInfo(username, filename, "N/A");
            return path;
        }

     

    }
}


