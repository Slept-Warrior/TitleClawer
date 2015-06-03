using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace TitleClawer
{
    [SuppressMessage("ReSharper", "PossibleNullReferenceException")]
    public class HttpHelper
    {
        #region 委托 事件
        public delegate void DgtProgValueChanged(long value);
        /// <summary>
        /// 进度改变事件
        /// </summary>
        public event DgtProgValueChanged OnProgValueChanged;
        #endregion

        #region 属性
        /// <summary>
        /// 代理
        /// </summary>
        public WebProxy Proxy { get; set; }
        /// <summary>
        /// Cookie
        /// </summary>
        public CookieContainer UserCookie { get; set; }
        /// <summary>
        /// 重试次数
        /// </summary>
        public int AfreshTime { get; set; }
        /// <summary>
        /// 错误次数
        /// </summary>
        public int ErrorTime { get; private set; }

        long _mProgValue;
        /// <summary>
        /// 当前读取字节
        /// </summary>
        public long ProgValue
        {
            get { return _mProgValue; }
            private set
            {
                _mProgValue = value;
                if (OnProgValueChanged != null)
                {
                    OnProgValueChanged(value);
                }
            }
        }
        /// <summary>
        /// 待读取最大字节
        /// </summary>
        public long ProgMaximum { get; private set; }

        #endregion

        #region 方法
        #region Get
        /// <summary>
        /// 获取HTML
        /// </summary>
        /// <param name="url">地址</param>
        /// <param name="accept">Accept请求头</param>
        /// <returns>Html代码</returns>
        public string GetHtml(string url, string accept)
        {
            return GetHtml(url, accept, Encoding.UTF8);
        }
        /// <summary>
        /// 获取HTML
        /// </summary>
        /// <param name="url">地址</param>
        /// <param name="accept">Accept请求头</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>Html代码</returns>
        public string GetHtml(string url, string accept, Encoding encoding)
        {
            return GetHtml(url, accept, encoding, 1024);
        }
        /// <summary>
        /// 获取HTML
        /// </summary>
        /// <param name="url">地址</param>
        /// <param name="accept">Accept请求头</param>
        /// <param name="encoding">字符编码</param>
        /// <param name="bufflen">数据包大小</param>
        /// <returns>Html代码</returns>
        public string GetHtml(string url, string accept, Encoding encoding, int bufflen)
        {
            ErrorTime = 0;
            return _GetHtml(url, accept, encoding, bufflen);
        }

        public bool CheckValidationResult(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            //直接确认，否则打不开
            return true;
        }
        /// <summary>
        /// 获取HTML
        /// </summary>
        /// <param name="url">地址</param>
        /// <param name="accept">Accept请求头</param>
        /// <param name="encoding">字符编码</param>
        /// <param name="bufflen">数据包大小</param>
        /// <returns>Html代码</returns>
        private string _GetHtml(string url, string accept, Encoding encoding, int bufflen)
        {
            try
            {
                AfreshTime = 2;
                ServicePointManager.ServerCertificateValidationCallback = CheckValidationResult;
                var myRequest = (HttpWebRequest)WebRequest.Create(url);
                myRequest.Proxy = Proxy;
                myRequest.Accept = accept;
                myRequest.Timeout = Program.Timeout * 1000;
                myRequest.AllowAutoRedirect = true;
                
                if (UserCookie == null)
                {
                    UserCookie = new CookieContainer();
                }
                myRequest.CookieContainer = UserCookie;
                var myResponse = (HttpWebResponse)myRequest.GetResponse();
                return _GetHtml(myResponse, encoding, bufflen);
            }
            catch (Exception erro)
            {
                if (erro.Message.Contains("连接") && AfreshTime - ErrorTime > 0)
                {
                    ErrorTime++;
                    return _GetHtml(url, accept, encoding, bufflen);
                }
                throw;
            }
        }
        /// <summary>
        /// 获取HTML
        /// </summary>
        /// <param name="myResponse"></param>
        /// <param name="encoding">字符编码</param>
        /// <param name="bufflen">数据包大小</param>
        /// <returns></returns>
        private string _GetHtml(HttpWebResponse myResponse, Encoding encoding, int bufflen)
        {
            using (var myStream = myResponse.GetResponseStream())
            {
                ProgMaximum = myResponse.ContentLength;
                string result = null;
                long totalDownloadedByte = 0;
                var by = new byte[bufflen];
                var osize = myStream.Read(by, 0, by.Length);
                while (osize > 0)
                {
                    totalDownloadedByte = osize + totalDownloadedByte;
                    result += encoding.GetString(by, 0, osize);
                    ProgValue = totalDownloadedByte;
                    osize = myStream.Read(by, 0, by.Length);
                }
                myStream.Close();
                return result;
            }
        }
        #endregion

        #region Post
        /// <summary>
        /// 回发(字符编码默认UTF-8)
        /// </summary>
        /// <param name="url">回发地址</param>
        /// <param name="postData">参数</param>
        /// <returns>Html代码</returns>
        public string PostPage(string url, string postData)
        {
            return PostPage(url, postData, Encoding.UTF8);
        }
        /// <summary>
        /// 回发
        /// </summary>
        /// <param name="url">回发地址</param>
        /// <param name="postData">参数</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>Html代码</returns>
        public string PostPage(string url, string postData, Encoding encoding)
        {
            return PostPage(url, postData, encoding, null);
        }

        /// <summary>
        /// 回发
        /// </summary>
        /// <param name="url">回发地址</param>
        /// <param name="postData">参数</param>
        /// <param name="encoding">字符编码</param>
        /// <param name="contentType"></param>
        /// <returns>Html代码</returns>
        public string PostPage(string url, string postData, Encoding encoding, string contentType)
        {
            ErrorTime = 0;
            return _PostPage(url, postData, encoding, contentType);
        }

        /// <summary>
        /// 回发
        /// </summary>
        /// <param name="url">回发地址</param>
        /// <param name="postData">参数</param>
        /// <param name="encoding">字符编码</param>
        /// <param name="contentType"></param>
        /// <returns>Html代码</returns>
        private string _PostPage(string url, string postData, Encoding encoding, string contentType)
        {
            try
            {
                if (contentType == null)
                {
                    contentType = "application/x-www-form-urlencoded";
                }
                var myRequest = (HttpWebRequest)WebRequest.Create(url);
                myRequest.Proxy = Proxy;
                if (UserCookie == null)
                {
                    UserCookie = new CookieContainer();
                }
                myRequest.CookieContainer = UserCookie;
                myRequest.Method = "POST";
                myRequest.ContentType = contentType;
                var b = encoding.GetBytes(postData);
                myRequest.ContentLength = b.Length;
                using (var sw = myRequest.GetRequestStream())
                {
                    try
                    {
                        sw.Write(b, 0, b.Length);
                    }
                    catch
                    {
                        // ignored
                    }
                }
                var myResponse = (HttpWebResponse)myRequest.GetResponse();
                return _GetHtml(myResponse, encoding, 1024);
            }
            catch (Exception erro)
            {
                if (erro.Message.Contains("连接") && AfreshTime - ErrorTime > 0)
                {
                    ErrorTime++;
                    return _PostPage(url, postData, encoding, contentType);
                }
                throw;
            }
        }
        #endregion
        #endregion
    }

    #region ArgsHandler

    public class CommandArgs
    {

        //---------------------------------------------------------------------

        /// <summary>

        /// Returns the dictionary of argument/value pairs.

        /// </summary>

        public Dictionary<string, string> ArgPairs
        {

            get { return _mArgPairs; }

        }

        private Dictionary<string, string> _mArgPairs = new Dictionary<string, string>();

        //---------------------------------------------------------------------

        /// <summary>

        /// Returns the list of stand-alone parameters.

        /// </summary>

        public List<string> Params
        {

            get { return _mParams; }

        }

        private List<string> _mParams = new List<string>();

    }

    /// <summary>

    /// Implements command line parsing

    /// </summary>

    public class CommandLine
    {

        //---------------------------------------------------------------------

        /// <summary>

        /// Parses the passed command line arguments and returns the result

        /// in a CommandArgs object.

        /// </summary>

        /// The command line is assumed to be in the format:

        ///

        /// CMD [param] [[-|--|\]&lt;arg&gt;[[=]&lt;value&gt;]] [param]

        ///

        /// Basically, stand-alone parameters can appear anywhere on the command line.

        /// Arguments are defined as key/value pairs. The argument key must begin

        /// with a '-', '--', or '\'. Between the argument and the value must be at

        /// least one space or a single '='. Extra spaces are ignored. Arguments MAY

        /// be followed by a value or, if no value supplied, the string 'true' is used.

        /// You must enclose argument values in quotes if they contain a space, otherwise

        /// they will not parse correctly.

        ///

        /// Example command lines are:

        ///

        /// cmd first -o outfile.txt --compile second \errors=errors.txt third fourth --test = "the value" fifth

        ///

        /// <param name="args">array of command line arguments</param>

        /// <returns>CommandArgs object containing the parsed command line</returns>

        public static CommandArgs Parse(string[] args)
        {

            var kEqual = new[] { '=' };

            var kArgStart = new[] { '-', '\\' };

            var ca = new CommandArgs();

            var ii = -1;

            var token = NextToken(args, ref ii);

            while (token != null)
            {

                if (IsArg(token))
                {

                    var arg = token.TrimStart(kArgStart).TrimEnd(kEqual);

                    string value = null;

                    if (arg.Contains("="))
                    {

                        // arg was specified with an '=' sign, so we need

                        // to split the string into the arg and value, but only

                        // if there is no space between the '=' and the arg and value.

                        var r = arg.Split(kEqual, 2);

                        if (r.Length == 2 && r[1] != string.Empty)
                        {

                            arg = r[0];

                            value = r[1];

                        }

                    }

                    while (value == null)
                    {

                        var next = NextToken(args, ref ii);

                        if (next != null)
                        {

                            if (IsArg(next))
                            {

                                // push the token back onto the stack so

                                // it gets picked up on next pass as an Arg

                                ii--;

                                value = "true";

                            }

                            else if (next != "=")
                            {

                                // save the value (trimming any '=' from the start)

                                value = next.TrimStart(kEqual);

                            }

                        }

                    }

                    // save the pair

                    ca.ArgPairs.Add(arg, value);

                }

                else if (token != string.Empty)
                {

                    // this is a stand-alone parameter.

                    ca.Params.Add(token);

                }

                token = NextToken(args, ref ii);

            }

            return ca;

        }

        //---------------------------------------------------------------------

        /// <summary>

        /// Returns True if the passed string is an argument (starts with

        /// '-', '--', or '\'.)

        /// </summary>

        /// <param name="arg">the string token to test</param>

        /// <returns>true if the passed string is an argument, else false if a parameter</returns>

        private static bool IsArg(string arg)
        {

            return (arg.StartsWith("-") || arg.StartsWith("\\"));

        }

        //---------------------------------------------------------------------

        /// <summary>

        /// Returns the next string token in the argument list

        /// </summary>

        /// <param name="args">list of string tokens</param>

        /// <param name="ii">index of the current token in the array</param>

        /// <returns>the next string token, or null if no more tokens in array</returns>

        private static string NextToken(string[] args, ref int ii)
        {

            ii++; // move to next token

            while (ii < args.Length)
            {

                var cur = args[ii].Trim();

                if (cur != string.Empty)
                {

                    // found valid token

                    return cur;

                }

                ii++;

            }

            // failed to get another token

            return null;

        }

    }

    #endregion

    [SuppressMessage("ReSharper", "ReturnValueOfPureMethodIsNotUsed")]
    [SuppressMessage("ReSharper", "AssignNullToNotNullAttribute")]
    class Program
    {

        public static string[] IpTable;

        public const string Helpout =
            "TiClaw names [-T[[:]attributes]] [-F[[:]attributes]] [-P[[:]attributes]]" +
            "\n" +
            "\n" +
            "  name\t\tIP列表文件名，默认为\"iplist.txt\"\n" +
            "  -T timeout\t指定HTTP访问的超时时间[timeout]，单位为秒，默认4秒\n" +
            "  -F filename\t指定保存输出文件的文件名[filename]，默认为result.csv\n" +
            "  -P ports\t指定扫描的端口，用\",\"分隔，如需https访问请在前加s，默认为80,s443"
            ;
        public static int Timeout = 10;
        public static string FileName = "iplist.txt", SaveFileName = "result.csv";
        public static string Ports = "80,s443";

        public static bool CheckPort(string ip, int port)
        {
            var tcpListen = false;
            //var udpListen = false;//设定端口状态标识位
            var myIpAddress = IPAddress.Parse(ip);
            var myIpEndPoint = new IPEndPoint(myIpAddress, port);
            try
            {
                var tcpClient = new TcpClient();
                tcpClient.Connect(myIpEndPoint);//对远程计算机的指定端口提出TCP连接请求
                tcpListen = true;
            }
            catch
            {
                // ignored
            }

            #region canceled

            //try
            //{
            //    var udpClient = new UdpClient();
            //    udpClient.Connect(myIpEndPoint);//对远程计算机的指定端口提出UDP连接请求
            //    udpListen = true;
            //}
            //catch
            //{
            //    // ignored
            //}

            #endregion

            return tcpListen;//|| udpListen;
        }

        static bool argHandler(string[] args)
        {
            var commandArg = CommandLine.Parse(args);

            var lparams = commandArg.Params;
            if (lparams.Count < 1)
            {
                Console.WriteLine(Helpout);
                return true;
            }
            for (var i = 0; i < lparams.Count; i++)
            {

                var commandArgString = commandArg.Params[i];
                FileName = commandArgString;
                if (commandArgString != "/?") continue;
                Console.WriteLine(Helpout);
                return true;
            }

            var argPairs = commandArg.ArgPairs;

            var keys = argPairs.Keys.ToList();

            foreach (var strKey in keys)
            {
                var strValue = argPairs[strKey];

                if ((strKey == "t") || (strKey == "T")) Timeout = Int32.Parse(strValue);
                if ((strKey == "s") || (strKey == "S")) SaveFileName = strValue;
                if ((strKey == "p") || (strKey == "P")) Ports = strValue;
            }
            return false;
        }

        [SuppressMessage("ReSharper", "PossibleNullReferenceException")]
        public static string[] GetTarget(string[] ipArr)
        {
            var target = new List<string>();
            foreach (var row in ipArr)
            {
                string[] ips;
                int mask;
                try
                {
                     ips = row.Split('/')[0].Split('.');
                     mask= Int32.Parse(row.Split('/')[1]);
                }
                catch
                {
                    target.Add(row);
                    continue;
                }
                
                var ip = Array.ConvertAll(ips, int.Parse);
                var count = Math.Pow(2, (32 - mask));
                for (var i = 0; i < count; i++)
                {
                    if (ip[3] == 0) ip[3] += 1;
                    if (ip[3] == 255)
                    {
                        ip[2] += 1;

                        ip[3] = 1;
                    }
                    if (ip[2] == 255)
                    {
                        ip[1] += 1;
                        ip[2] = 1;
                    }
                    if (ip[1] == 255)
                    {
                        ip[0] += 1;
                        ip[1] = 1;
                    }
                    target.Add(ip[0].ToString() + "." + ip[1].ToString() + "." + ip[2].ToString() + "." + ip[3].ToString());

                    ip[3] += 1;
                }
            }
            return target.ToArray();
        }
        public static void LoadFile(string file)
        {
            try
            {
                var aFile = new FileStream(file, FileMode.Open);
                var sr = new StreamReader(aFile);
                IpTable = sr.ReadToEnd().Split('\n');
                var i = 0;
                foreach (var ip in IpTable)
                {
                    IpTable[i++] = ip.Replace("\r", string.Empty);
                }
                sr.Close();
            }
            catch (IOException ex)
            {
                Console.WriteLine("An IOException has been thrown!");
                Console.WriteLine(ex.ToString());
                Console.ReadLine();
            }
        }

        static string GetCodec(string code)
        {
            var charSetMatch = Regex.Match(code, "<meta([^<]*)charset=([^<]*)\"", RegexOptions.IgnoreCase | RegexOptions.Multiline);
            var codec = charSetMatch.Groups[2].Value.Replace("\"", String.Empty);
            if (codec == "") codec = "UTF-8";
            return codec;
        }

        static void PickTit(string page, out string title)
        {
            var titlestart = page.Substring(page.IndexOf("<title", StringComparison.OrdinalIgnoreCase));
            title = titlestart.Substring(1 + titlestart.IndexOf(">", StringComparison.Ordinal), titlestart.IndexOf("</title>", StringComparison.OrdinalIgnoreCase) - 1 - titlestart.IndexOf(">", StringComparison.Ordinal));
            title =
                title.Replace("\r", String.Empty)
                     .Replace("\n", String.Empty)
                     .Replace("\t", String.Empty)
                     .Replace(",", "，");
        }
        public static bool Sendhttp(string webAddr, bool ssl, string port, out string title)
        {
            try
            {
                string redir;
                var http = new HttpHelper();
                if (ssl)
                    webAddr = @"https://" + webAddr + ":" + port;
                else
                    webAddr = @"http://" + webAddr + ":" + port;
                var pageHtml = http.GetHtml(webAddr, "*/*", Encoding.Default, 20480);
                if (!Equals(Encoding.Default, Encoding.GetEncoding(GetCodec(pageHtml)))) pageHtml = http.GetHtml(webAddr, "*/*", Encoding.GetEncoding(GetCodec(pageHtml)), 20480);
                if (pageHtml.Contains("window.location"))
                {
                    redir = pageHtml.Substring(11+pageHtml.IndexOf(".location=\"", StringComparison.Ordinal));
                    redir = redir.Substring(0, redir.IndexOf('\"'));
                    if (redir.Contains("http://") || redir.Contains("https://")) webAddr = redir;
                    webAddr = webAddr + "/" + redir;
                    pageHtml = http.GetHtml(webAddr, "*/*", Encoding.Default, 20480);
                    if (!Equals(Encoding.Default, Encoding.GetEncoding(GetCodec(pageHtml)))) pageHtml = http.GetHtml(webAddr, "*/*", Encoding.GetEncoding(GetCodec(pageHtml)), 20480);
                }
                PickTit(pageHtml, out title);
                return true;
            }
            catch(WebException ex)
            {
                title = "";
                if (!ex.ToString().Contains("401")) return false;
                var header = ex.Response.Headers.ToString();
                var temp = header.Substring(header.IndexOf("realm=\"", StringComparison.Ordinal) + 7);
                title = "[HTTP401]REALM: "+temp.Substring(0, temp.IndexOf("\"", StringComparison.Ordinal));
                return true;
            }
        }
        public static string SubString(string toSub, int startIndex, int length)
        {

            var subbyte = Encoding.Default.GetBytes(toSub);

            var sub = Encoding.Default.GetString(subbyte, startIndex, length);

            return sub;

        }

        public static string[] DetPort(string portStr, out int count)
        {
            var port = portStr.Split(',');
            count = port.Count();
            return port;
        }
        public static int Text_Length(string text)
        {
            var len = 0;

            for (var i = 0; i < text.Length; i++)
            {
                var byteLen = Encoding.Default.GetBytes(text.Substring(i, 1));
                if (byteLen.Length > 1)
                    len += 2;  //如果长度大于1，是中文，占两个字节，+2
                else
                    len += 1;  //如果长度等于1，是英文，占一个字节，+1
            }

            return len;
        }
        static void Main(string[] args)
        {
            var count = 0;
            int totalport;
            var result = "";
            if (argHandler(args)) return; 
            //argHandler(args);
            LoadFile(FileName);
            var ports = DetPort(Ports,out totalport);
            var targets = GetTarget(IpTable);
            var totalcount = (totalport * targets.Count()).ToString();
            Parallel.For(0, targets.Count(), i =>
            {
                foreach (var port in ports)
                {
                    string title;
                    string portstr;
                    if (port.Substring(0, 1) == "s")
                    {
                        var shit = port.Substring(1);
                        if (Sendhttp(targets[i], true, shit, out title))
                        {
                            if (title == "") title = "No Title";
                            result += (targets[i] + ","+shit+"," + title + "\n");

                        }
                        if (title == "")
                        {
                            title = "No Title";
                        }
                        else if (Text_Length(title) > 30)
                        {
                            title = SubString(title, 0, 30).Substring(0, SubString(title, 0, 30).Length - 1) + "...";
                        }
                        portstr = ":" + shit + "\t" + (targets[i].Length > 11 ? "" : "\t");
                        Console.WriteLine((++count) + "/" + totalcount + "\t\t" + targets[i] + portstr + "    " + title);
                    }
                    else
                    {
                        if (Sendhttp(targets[i], false, port, out title))
                        {
                            if (title == "") title = "No Title";
                            result += (targets[i] + "," + port + "," + title + "\n");
                        }
                        if (title == "")
                            title = "No Title";
                        else if (Text_Length(title) > 30)
                            title = SubString(title, 0, 30).Substring(0, SubString(title, 0, 30).Length - 1) + "...";
                        portstr = ":" + port + "\t" + (targets[i].Length > 12 ? "" : "\t");

                        Console.WriteLine((++count) + "/" + totalcount + "\t\t" + targets[i] + portstr + "    " + title);
                    }
                }
            });
            Console.WriteLine("done");
            while (true) { 
            try
            {
                var sw = new StreamWriter(SaveFileName);
                sw.Write(result);
                sw.Close();
                break;
            }
            catch
            {
                Console.WriteLine("文件无法保存，请更改文件名:");
                SaveFileName = Console.ReadLine();
            }
            }

        }
    }
}
