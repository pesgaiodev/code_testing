<?php
session_start();

class activedirectorysync 
{
    var $Schema= "db_schema";
    var $debugFile = null;

    public function _getParams($param,$unit)
    {
        if(!isset($_SESSION['language']) || $_SESSION['language']=='')
        {
          $_SESSION['language']=2;
        }

        $sql = "select ".$this->Schema.".get_param_value(".$param.", ".$unit."::bigint, ".$_SESSION['language']."::bigint, 0::smallint ) as values";
        $resultParams = $this->query($sql);

        if(isset($resultParams[0]['values']))
        {
            return $resultParams[0]['values'];
        }
        else
        {
            return 0;
        }
    }

	public function get_members()
	{
        // Active Directory server name
        $ldap_host = $this->_getParams('859',0);

        // domain, for purposes of constructing $user
        $ldap_usr_dom = $this->_getParams('862',0);

        // Active Directory user
        $user = $this->_getParams('863',0);

        // Active Directory Password
        $password = $this->_getParams('864',0);

        //BASE DN
        $base_dn = $this->_getParams('860',0);

		$ldap = ldap_connect($ldap_host) or die("Could not connect to ".$ldap_host. "\r\n");;

        fwrite($this->debugFile, print_r($ldap,1) . "\r\n");

		ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION,3);
		ldap_set_option($ldap, LDAP_OPT_REFERRALS,0);

        if ($ldap)
        {
            fwrite($this->debugFile, "User:" . $user . " - Domain:" . $ldap_usr_dom . " - Password:" . $password . "\r\n");

            // binding to ldap server
            $ldapbind = ldap_bind($ldap, $user . $ldap_usr_dom, $password);

            // verify binding
            if ($ldapbind)
            {
                fwrite($this->debugFile, "LDAP bind successful...". "\r\n");
            }
            else
            {
                fwrite($this->debugFile, "LDAP bind failed...". "\r\n");
            }
        }

		$attr = Array();
		$attr[0] = "dn";

        $results = ldap_list($ldap,$base_dn,"(objectClass=*)",$attr);

        fwrite($this->debugFile, "results:" . print_r($results,1) . "\r\n");

        $member_list = ldap_get_entries($ldap, $results);

        fwrite($this->debugFile, "member_list:" . print_r($member_list['count'],1) . "\r\n");

		$count = $member_list['count'];
		$i = 0;

		$usersArray = Array();

		$attr2 = Array();
		$attr2[0] = "*";
		$attr2[1] = "+";

		if ($count > 1)
		{
			for($i=0;  $i < $count; $i++)
			{
				$dn = $member_list[$i]['dn'];
				$resultsMember = ldap_read($ldap,$dn,"(objectClass=*)",$attr2);
				$memberDetails = ldap_get_entries($ldap, $resultsMember);

				$user = Array();

				$user['name'] = utf8_decode($memberDetails[0]['name'][0]);
				$user['displayname'] = utf8_decode($memberDetails[0]['displayname'][0]);
				$user['mail'] = utf8_decode($memberDetails[0]['mail'][0]);
				$user['samaccountname'] = $memberDetails[0]['samaccountname'][0];
				$user['status'] = $memberDetails[0]['msrtcsip-userenabled'][0];// 
				$userprincipalname = $memberDetails[0]['userprincipalname'][0];
				$arrPrincipalName = explode("@",$userprincipalname);

				$user['kerberoslogin'] = $user['samaccountname'] . "@" . strtoupper($arrPrincipalName[1]);

				if ($this->addUserExist($usersArray,$user) == "true")
				{
					$usersArray[] = $user;
				}
			}
		}

		ldap_close($ldap);
		return $usersArray;
	}
	
	public function addUserExist($arr, $user)
	{
		if ($user['displayname'] == "" || $user['samaccountname'] == "" )
		{
			return "false";
		}
	
		foreach($arr as $us)
		{
			if ($us['samaccountname'] == $user['samaccountname'])
			{
				return "false";
			}
		}
		
		return "true";
	}

    public function syncUsers()
    {
         $this->db->StartTrans();

		 $myFileSyncUsers = "console/dev/activedirectorySyncUsers".date('Ymd').".log";
		 $this->debugFile = fopen($myFileSyncUsers, 'a+');

         $res = $this->_getParams('865','0');
		 fwrite($this->debugFile, print_r($res,true) . "\r\n");

         if ($res[0] != "1")
         {
            return;
         }

         $arr = array();
         $arr = $this->get_members();

         $defaultpass = md5("secret#default&p@ss");
		 fwrite($this->debugFile, print_r($arr,true) . "\r\n");

         foreach($arr as $user)
         {
			$name = trim($user['name']);
            $displayname = trim($user['displayname']);
            $email = trim($user['mail']);
            $login = trim($user['samaccountname']);
            $status = trim($user['status']);
			$kerberoslogin = trim($user['kerberoslogin']);

            $sql = "select *
            from {$this->Schema}.users
			where
			(
			trim(upper(login)) = trim(upper(".$this->db->qstr($login)."))
			OR
			trim(upper(email)) = trim(upper(".$this->db->qstr($email)."))
			OR
			trim(upper(name)) = trim(upper(".$this->db->qstr($displayname)."))
            OR
            trim(upper(kerberos_login)) = trim(upper(".$this->db->qstr($kerberoslogin)."))
			)
			and status = 'ACTIVE'";
			
            $ruser = $this->query($sql);
			fwrite($this->debugFile, $sql . "\r\n");

            if (count($ruser) == 0)
            {
				fwrite($this->debugFile, "Não existe! \r\n");
                if ($displayname != "" && $login != "")
                {
                    $arr[]['user'] = $login;
                    $arr[]['name'] = $displayname;
                    $arr[]['mail'] = $email;
                    $arr[]['status'] = $status;

                    $sqlInsert = "INSERT into {$this->Schema}.users (name,pass,login,email,kerberos_login,new_pass)
                                  VALUES (".$this->db->qstr($displayname).",".$this->db->qstr($defaultpass).",".$this->db->qstr($login).",".$this->db->qstr($email).",".$this->db->qstr($kerberoslogin).",true)";

                    $this->noQuery($sqlInsert);
					fwrite($this->debugFile, $sqlInsert . "\r\n");
                }
            }
            elseif (count($ruser) == 1)
            {
               if ($status == "FALSE")
               {
                   $id = $ruser[0]['id'];
                   $sqlupdate = "UPDATE {$this->Schema}.users set status = 'INACTIVE' where id = " .$id;
                   $this->noQuery($sqlupdate);
				   fwrite($this->debugFile, $sqlupdate . "\r\n");
               }
            }
         }

        if ($this->db->HasFailedTrans())
        {
            $arr[0]="-1";
        }
        else
        {
            $arr[0]="1";
        }

        $this->db->CompleteTrans();
        return $arr;
    }

}

$ad = new activedirectorysync();
$res = $ad->syncUsers();

?>
