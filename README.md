# SOC Automation Project

A Security Operations Center, or SOC for short, is a centralized team of IT Security professionals who monitor and manage an organization’s infrastructure. In this series of write-ups, we’ll build one! In part 1 we’ll look at a basic design, install Windows 10 and sysmon, and deploy two VMs for wazuh and TheHive using Linode.

First, we need a design or a data flow for our SOC. I spent 5 minutes on draw.io and came up with this

![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/soc%20automation%20diagram.png)

Now that we have a design for our SOC lab, we can start by installing our Windows client, with sysmon. I will install Windows 10 on VMWare, but you could do it on VBox, or in the cloud. For Wazuh and TheHive, I will deploy them on the cloud (Linode by Akamai, comes with $100 free credit, valid for 2 months, which should be enough for our project)

To install sysmon, download it from here. I also downloaded this configuration file.

Extract the contents in the sysmon zip folder into a file along with the configuration file. Open Powershell as an administrator, and cd into the file you put sysmon into. Then, run this command:
```
.\Sysmon64.exe -i sysmonconfig.xml
```

When prompted to accept terms, accept it, and sysmon should install within a minute. Now let’s set up wazuh and TheHive. I will do this on the cloud with Linode, but you could do it locally too, but that is out of scope for this write-up.

First, create your account, once you’re inside, click on Create Linode. Choose a data center, and for OS, choose Ubuntu 22.04 LTS. For the plan, choose Linode 8GB under shared cpu. My settings look like this:

![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/2nd.png)

Enter a label, and set a root password, you want this to be strong. Scroll down and under firewall, click on Create Firewall, and enter the following settings:

![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/3rd.png)

Click on Create Firewall.

This is what the summary looks like to me:

![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/4th.png)

Click on Create Linode. Then go to your firewall, and click on add inbound rule, then copy the following rule:

![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/5th.png)

Replace IP with your personal computer’s public IP. Click on add rule. (NOTE: you can also set ports to ALL instead of just ssh)

Similarly, add another rule, but this time, under protocols, choose UDP. Then, in the main screen, change Inbound Policy to Drop. Click on save changes. Now we have a cloud instance that can only receive packets from us.

Then, on the main linode screen, click on your VM, and click on Launch LISH console. Then, enter root for user, and enter the password you set earlier.

Run the following command:
```
apt-get update && apt-get upgrade
```
Repeat the steps and create another VM for TheHive, except this time, don’t create another firewall, just use the same one.

First, let’s install Wazuh. Click on your Wazuh VM and click on LISH console. Then, run this command:

```
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

(NOTE: This is for Wazuh 4.7, if you want to install a different version, check the Wazuh website)

This will take a couple of minutes. Once the installation is finished, access the wazuh dashboard by going to this link on your browser:
```
https://<linode-public-ip>:443
```

Replace <linode-public-ip> with your wazuh VM’s public IP, which can be found on the main dashboard. Type in admin for the user, and for the password, enter the one shown on the screen after wazuh installation

To change the password to something easy to type (remember, we have a firewall, no one else can access this dashboard, and you can get away with a weak and easy password), get the wazuh-passwords-tool:
```
curl -so wazuh-passwords-tool.sh https://packages.wazuh.com/4.4/wazuh-passwords-tool.sh
```

Then run the following command:
```
bash wazuh-passwords-tool.sh -u admin -p <password>
```
Finally, restart wazuh service:
```
systemctl restart wazuh-manager
```

Go back to the wazuh dashboard, it should look like this:

![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/6th.png)

We’ll configure wazuh later in this write-up

Now, let’s set up TheHive. Go to your hive VM, and install the dependencies:
```
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
```

Install Java
```
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

Install Cassandra
```
wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```

Install ElasticSearch
```
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```
Now let’s configure ElasticSearch. Create a jvm.options file under /etc/elasticsearch/jvm.options.d and put the following configurations in that file.
```
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
```

Finally, Install TheHive
```
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```

In your VM running TheHive, edit this file:
/etc/cassandra/cassandra.yaml

Change the cluster name to whatever you like (soc_auto_lab for me), and change the listen_address to the public IP of your vm. Also change rpc address to the same public IP.

Finally, under seed_provider, change the -seeds to your public IP (remember to leave the :7000 port as it is)

Next, run these commands:
```
systemctl stop cassandra.service
rm -rf /var/lib/cassandra/*
systemctl start cassandra.service
systemctl status cassandra.service
```

Next, let’s configure elasticsearch, edit this file:
/etc/elasticsearch/elasticsearch.yml

Uncomment the “cluster.name” line and give it a name, I will be naming it thehive. Also, uncomment the “node.name” line, I will leave the name as node-1

Next, uncomment the network.host line, and enter the public IP of your vm. Uncomment the http.port line, and leave it as it is. Now, we need to uncomment the cluster.initial_master_nodes line, and remove the “node-2”, and just leave node-1

Save the file, and start elasticsearch:
```
systemctl start elasticsearch
systemctl enable elasticsearch
systemctl status elasticsearch
```

Now we can finally configure thehive, but first, we need to give it the right permissions so that it can access the right files, run this command:

```
chown -R thehive:thehive /opt/thp
```

Now edit this file:
```
/etc/thehive/application.conf
```

Under db.janusgraph, change the hostname to the public IP under cql, change the cluster-name to what you set it before during cassandra configuration.

Under index.search, change the hostname again. Under application.baseUrl, change the localhost to public IP again

Now, we can start thehive:
```
systemctl start thehive
systemctl enable thehive
systemctl status thehive
```

Finally, check if everything is running:
```
systemctl status cassandra
systemctl status elasticsearch
systemctl status thehive
```

They should all be active and running.

Now we can finally check thehive webgui: http://<linode-ip>:9000

The default credentials:

```
user: admin@thehive.local
password: secret
```
![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/7th.png)

Now that we’ve configured thehive, let’s connect our win10 agent with wazuh. First, login to wazuh:
```
https://<linode-ip>:443
```

At the top, there should be a message saying “No agents were added to this manager”, click on Add Agent next to it. Choose Windows (since our client was win10, choose linux if you setup a linux VM)

For the server address, enter wazuh linode’s public IP. Give it an agent name, and leave the group at default. Then copy the command and run it in your windows client. Make sure to run the command in powershell, as an administrator.

Then finally run the last command that starts the agent. In your wazuh dashboard, it should say you have 1 active agent.

![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/8th.png)

To summarize, in part 2, we did the following:

-> Configured and deployed wazuh.
-> Configured cassandra, elasticsearch and thehive.
-> Installed our first wazuh agent on our win10 client.

In our win10 client, head to Program Files (x86), ossec-agent, and find the file that says ossec.conf. Open it with notepad to edit it, but before you do, make sure to make a backup of the file.

Let’s configure it to ingest our sysmon logs
Find the line that says Log analysis

Under log analysis, paste this to ingest sysmon logs:
```
 <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
```
I will also add this for monitoring powershell logs too:
```
<localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
```

For the sake of there being simple logs, I will remove the “Application”, “System” and “Security”. So in the end, we will be ingesting powershell, sysmon logs, and active response.

Now save the file and go to Services, and restart the Wazuh service

Now head to the wazuh dashboard, and click on Security events -> events.
In the sidebar on the left, make sure wazuh-alerts-* is selected. At

With the search-bar at the top search for sysmon to see sysmon events

As you can see, we already have 53 sysmon logs ingested into wazuh.

Now, let’s generate some telemetry with mimikatz. Disable the AV or add your downloads folder to exclusion in your win10 client or it will flag and delete mimikatz. Download mimikatz from here. Under releases, download mimikatz_trunk.zip. You may also have to disable security protection from the browser.

Then, open powershell as administrator and cd into the mimikatz folder (after extracting it). And run mimikatz. If you now go to wazuh and search for mimikatz, you will find that there are no logs. This is because wazuh by default does not log anything unless there is an alert or an event, which we have to create for mimikatz. Or we can have wazuh log everything, even if it’s not an event. To do that, we need to configure wazuh on our wazuh VM.

First, make a backup of the config file:
```
cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf
```

Then edit the config file, and change no to yes for these 2 fields: “logall” and “logall_json”

Then restart wazuh:
```
systemctl restart wazuh-manager.service
```

Now, wazuh will log everything, not just events/logs. But, these logs need to be ingested, to do that, edit this file:
/etc/filebeat/filebeat.yml
Under filebeat.modules, change archives enabled to true and restart filebeat:
```
systemctl restart filebeat
```

Now, head to wazuh dashboard and on the sidemenu on the left, click on stack management. Click on Index Patterns, and create Index. Then, type wazuh-archives-* behind the * that’s already there, it should look like this:


![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/21.png)

Click on the next step. For the time field, scroll down and click on timestamp, and hit create index. Then, in the hamburger menu on the left, click on discover, and where it says wazuh-alerts-*, click on the down arrow next to it and select our newly created index.

Here, you can search for mimikatz, and you should see logs related to mimikatz if you ran it earlier.

Now, let’s create an alert, we’ll do this by using the originalFileName tag that can be found if you expand a log related to mimikatz

To create this alert, go to the home page, click on the down arrow next to wazuh then click on management, and click on rules. Then click on manage rules files. Type sysmon at the top and find the xml file that says sysmon_id_1.xml (or 0800-sysmon_id_1.xml). Click on the eye icon, and copy a <rule> section. We will edit this rule to have it detect mimikatz. Now go back, and click on custom rules. Click on the pencil icon to edit the first file (there should only be one) and paste the rule section that you copied. Change the rule id to 100002 (note: custom rules always start with 100000). Then change the level to 15 (15 is the highest severity level you can have)

For the field name enter: `win.eventdata.originalFileName`. For type, leave >(?i) and replace the rest with mimikatz\\.exe

Remove the next line that says no_full_log. Change the description to whatever you like. Change the mitre ID to T1003 which stands for credential dumping (which is what mimikatz is used for). Then save the file, the rule we added should look something like this:
```
  <rule id="100002" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz detection</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
```

After saving it, click on restart

Now go to your home page, and head to security events, there should be none. Now let’s test our rule, run mimikatz on your client, and wait for wazuh to ingest the logs and detect mimikatz.

As you can see, wazuh successfully detected mimikatz:

![](https://github.com/prakharvr02/SOC-Automation/blob/17496cf1b61b30a902879751a78632bcfee9b060/Images/9th.png)

Head to shuffler.io and create an account. Then create a new workflow and name it whatever you want.

Add webhook and rename it, and click on the blue dot, drag it and connect it to the change me icon.

Click on the change me icon and under the “find actions” field, enter repeat back to me and enter “$exec”

Now click on webhook, and copy the webhook url. We need to paste this into wazuh’s config file.
```
/var/ossec/etc/ossec.conf
```

Add this above the <alert> tag.
```
<integration>
  <name>shuffle</name>
  <hook_url> YOUR HOOK URL HERE </hook_url>
  <rule_id>100002</rule_id>
  <alert_format>json</alert_format>
</integration>
```

Replace “YOUR HOOK URL HERE” with the hook url from shuffle, and restart wazuh.

Then, run mimikatz on your client to trigger the alert, and go to shuffle and click on the run logo at the bottom to see if our integration worked.

If it worked, you should get a result like this:

![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/11th.png)

As you can see, we have successfully extracted the hash. We can now forward this to a virustotal integration to check if it is virus.

But first, create a virustotal account, because you need an API key.

Then add virustotal from the search bar on the top left, and choose Get a hash report under actions. Make sure to add your API key.

Under id, click on the plus icon and click on the arrow next to your “change me” or whatever you named it earlier that has the sha256 regex and select list. It should look something like this (I named mine sha_256_regex):
$sha_256_regex.group_0.#

Go ahead and save the workflow, click on the person icon again, select the recently run mimikatz workflow, and hit rerun workflow. Then click on the virustotal output, it should look something like this:

![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/12th.png)

Clicking on the left arrow button, we can see what virustotal returned:

![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/13th.png)

Now let’s forward this alert to TheHive. Login to your hive dashboard

Let’s create a new organization, click on the plus button at the top left. Name it whatever and click on create. Then click on the newly created organization and click on the plus icon again to add a user.

Make the user an analyst and give it whatever login and name you want.

Add another user and this time, change the type from normal to service, and name it whatever you want. Make it analyst again and hit confirm

Next, hover over the users and click on preview, scroll down, and you will see a password field, create a password.

Then, for the SOAR user, create and copy the API key and store it somewhere, we will be using this to connect shuffle and thehive

Now logout of the account and login to your normal account, not the service one

On the left, click on alerts, you can see it’s empty. This is where our alerts will come in. Go back to shuffle and add thehive from the search bar at the top left.

Click on thehive, and click on authenticate and enter your api key that we copied earlier. For the url, enter the public ip of thehive vm along with the port 9000

Under find actions, select create alert.

Connect virustotal with the hive

For the description, we will put the date, click on the plus icon, go to execution argument, and find the utcTime variable: $exec.text.win.eventdata.utcTime.

For the Source, put this:
$exec.text.win.system.computer

For severity and pap, put 2
For sourceref put: “Rule: 100002”. Set status to New

Now, test the workflow again

You should see an alert in thehive:

![](https://github.com/prakharvr02/SOC-Automation/blob/main/Images/14th.png)












