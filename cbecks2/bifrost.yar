rule bifrost {
   meta:
      description = "Detect bifrost"
      author = "cbecks2"
      reference = "https://github.com/its-a-feature/bifrost"
      date = "2021-10-21"
   strings:
      $s1 = "-username a.test -password 'mypassword' -domain DOMAIN.COM" fullword ascii
      $s2 = "-username a.test -domain DOMAIN.COM" fullword ascii
      $s3 = "[-] Missing required argument -targetUser" fullword ascii
      $s4 = "[*] Dumping ticket from new CCache and removing entry" fullword ascii
      $s5 = "-[KerbApp12 initForProxyWithTicket:Service:TargetDomain:InnerTicket:]" fullword ascii
      $s6 = "initForProxyWithTicket:Service:TargetDomain:InnerTicket:" fullword ascii
      $s7 = "-spn [target SPN] (if this isn't specified, just a forwardable S4U2Self ticket is requested as targetUser)" fullword ascii
      $s8 = "[-] KDC_ERR_PREAUTH_FAILED: Bad Username/Password combination" fullword ascii
      $s9 = "[-] Error: trying to move outside of blob range in getNextAsnBlob while moving base forward" fullword ascii
      $s10 = "./bifrost -action [dump | list | askhash | describe | asktgt | asktgs | s4u | ptt | remove | asklkdcdomain]" fullword ascii
      $s11 = "[-] KDC_ERR_KEY_EXPIRED: User's password expired. Reset it before you can get a TGT" fullword ascii
      $s12 = "-[KerbApp12 createPAForUserKey:TargetUser:Realm:]" fullword ascii
      $s13 = "initWithTicket:Service:TargetDomain:Kerberoasting:" fullword ascii
      $s14 = "createPAForUserKey:TargetUser:Realm:" fullword ascii
      $s15 = "-[KerbApp12 initWithTicket:Service:TargetDomain:Kerberoasting:]" fullword ascii
      $s16 = " -username [username] -LKDCIP [remote host IP] -password [user's password] -cacheName [cache name to store info]" fullword ascii
      $s17 = "[-] Missing -password" fullword ascii
      $s18 = "[*] Requesting password: %s" fullword ascii
      $s19 = "[-] Failed to get response from remote LKDC" fullword ascii
      $s20 = "__mh_execute_header" fullword ascii
   condition:
      uint16(0) == 0xfacf and filesize < 1000KB and
      8 of them
