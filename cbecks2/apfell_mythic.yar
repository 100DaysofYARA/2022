rule apfell_mythic {
   meta:
      description = "May detect a Mythic/Apfell C2 Agent"
      author = "cbecks2"
      date = "2021-10-21"
   strings:
      $x1 = "exports.shell_elevated = function(task, command, params){" fullword ascii
      $x2 = "exports.spawn_drop_and_execute = function(task, command, params){" fullword ascii
      $s3 = "b64_exported_public = b64_exported_public.base64EncodedStringWithOptions(0).js; // get a base64 encoded string version" fullword ascii
      $s4 = "exports.persist_loginitem_allusers = function(task, command, params){" fullword ascii
      $s5 = "exports.spawn_download_cradle = function(task, command, params){" fullword ascii
      $s6 = "exports.test_password = function(task, command, params){" fullword ascii
      $s7 = "exports.list_users = function(task, command, params){" fullword ascii
      $s8 = "exports.system_info = function(task, command, params){" fullword ascii
      $s9 = "            var full_command = \"echo \\\"\" + base64_command + \"\\\" | base64 -D | /usr/bin/osascript -l JavaScript &amp;\";" fullword ascii
      $s10 = "//console.log(\"posting: \" + sendData + \" to \" + urlEnding);" fullword ascii
      $s11 = "        return {\"user_output\": \"Created temp file: \" + temp_file + \", started process and removed file\", \"completed\": tr" ascii
      $s12 = "        return {\"user_output\": \"Created temp file: \" + temp_file + \", started process and removed file\", \"completed\": tr" ascii
      $s13 = "//console.log(\"about to load commands\");" fullword ascii
      $s14 = "                    return {\"user_output\":\"Error trying to read /Library/LaunchAgents: \" + error.toString(), \"completed\": " ascii
      $s15 = "                    \"app.doShellScript(\\\" osascript -l JavaScript -e \\\\\\\"eval(ObjC.unwrap($.NSString.alloc.initWithDataEn" ascii
      $s16 = "exports.download = function(task, command, params){" fullword ascii
      $s17 = "exports.run = function(task, command, params){" fullword ascii
      $s18 = "                    return {\"user_output\":\"Error trying to read /Library/LaunchAgents: \" + error.toString(), \"completed\": " ascii
      $s19 = "this.pid = this.procInfo.processIdentifier;" fullword ascii
      $s20 = "exports.jscript = function(task, command, params){" fullword ascii
   condition:
      uint16(0) == 0x2f2f and filesize < 300KB and
      1 of ($x*) and 4 of them
}
