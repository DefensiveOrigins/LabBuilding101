# Welcome to Lab Building 101

This repo was created for the gracious folks at Wild West Hackin' Fest, who picked us up, dusted us off and said "here's another chance guys, go get 'em!" ...and who gave us an opportunity to run a rapid fire workshop about lab building.

Anyway, here's the Defensive Origins crew builds labs!



# Building a Lab on Azure with ARM

Time to deploy: **Approximately 30-60 minutes**

Authenticate to your Azure portal: 

| &#x1f30e; URL | Browser on Students Local System |
|---------------|----------------------------------|
```url
https://portal.azure.com
```

Then, goto the hosted ARM template resource page on a new browser tab:.

| &#x1f30e; URL | Browser on Students Local System |
|---------------|----------------------------------|
```url
https://www.doazlab.com
```

About half way down the page, click the **Deploy to Azure** button.

| ![www.doazlab.com Lab Build Launcher](img/deploy-doazlab-com.jpg) | 
|------------------------------------------------|

Select your subscription, resource group, and location.  Document this location, it will be needed later in class.

| ![Subscription, Resource Group, Location](img/deploy-sub-rg-location.jpg) | 
|------------------------------------------------|

The default VM size is B2s, which are burstable, low cost, and efficient VMs. You can bump this up to larger should you choose. 

| ![VM Size Selection](img/deploy-vm-size.jpg) | 
|------------------------------------------------|

Your next configuration option is the network ranges allowed to access this lab's public IP addresses. We will investigate some Internet-based threats later and recommend leaving this wide open to the configured all zeroes (0.0.0.0/0) range. 

| ![Lab Environment Allowed Networks](img/deploy-allowed-networks.jpg) | 
|------------------------------------------------|

One more click will bring you to the validation check. After a moment, you can click on Create to start the build process for your ADD Lab Environment.

| ![Lab Config Validation](img/deploy-validation.jpg) | 
|------------------------------------------------|

The process takes between 25 and 30 minutes to fully deploy. The deployment confirmation shown next is indicative of a successful build. 

| ![Lab Deployment Confirmation](img/deploy-confirmation.jpg) | 
|------------------------------------------------|

The **Outputs** option in the left navigation tree includes the access details you will need for SSH and RDP access into the lab environment. Document these IP addresses, you will need them later to access your lab infrastructure.

| ![Lab Deployment Outputs: Access Details](img/deploy-outputs.jpg) | 
|------------------------------------------------|

A visual aid for your lab deployment is shown in the next image. 

| ![Lab Deployment Visual](img/lab-visual.jpg) | 
|------------------------------------------------|



# Connecting to Infrastructure 

<!-- DO-CREDENTIAL-REMINDER-START -->
<Details><summary>

## &#x1F512; Lab Credentials

</summary><blockquote>

### &#x1FA9F; Windows credentials

When logging into the Windows system, use the following credentials.

```Win-creds
doazlab\doadmin
DOLabAdmin1!
```

### &#x1F427; Linux credentials

When logging into the Linux system, use the following credentials.

```Linux-creds
doadmin
DOLabAdmin1!
```

</blockquote></details>

<!-- DO-CREDENTIAL-REMINDER-END -->
<Details><summary>

## &#x2460; Lab Deployment Network Connectivity 

</summary><blockquote>

The screenshot in this section demonstrates the output values from the course ARM template deployemnt. 

You will need all of these at various points throughout the course material. You should keep them handy in a notes document or similar quick-reference.

| ![Outputs: IP Address Details](img/outputs-IP-details.jpg) | 
|------------------------------------------------|


&#x21E8; *Step Complete, Go to the next step!*

</blockquote></details>


<Details><summary>

## &#x2461; Establish RDP Connections (from Linux) 

</summary><blockquote>

Establish RDP to the workstation and domain controller (Linux with Remmina)

From Linux, you can use the Remmina remote desktop (RDP) client software.

| ![Remmina RDP Connection Manager](img/remmina-client.jpg) | 
|------------------------------------------------|

| &#x26a0; Note | Be sure to include the domain on the initial RDP connections.|
|---------------|--------------------------------------------------------------|

```Win-creds
doazlab\doadmin
DOLabAdmin1!
```

Establish an RDP connection to the IP address of your lab's domain controller. You will be prompted to accept a certificate that should match **DC01.doazlab.com**.

| ![DC Certificate Offer](img/linux-rdp-cert-dc.jpg) | 
|------------------------------------------------|

Establish an RDP connection to the IP address of your lab's workstation. You will be prompted to accept a certificate that should match **WS05.doazlab.com**.

| ![Workstation Certificate Offer](img/linux-rdp-cert-ws.jpg) | 
|------------------------------------------------|

The domain controller will prompt you to accept the discovery settings. Your lab is isolated and our guidance is to click **Yes**. The course authors do not believe choosing **No** will affect any of the course content.

| ![Domain Controller Initial Desktop](img/linux-rdp-initial-dc-desktop.jpg) | 
|------------------------------------------------|

The first login to the workstation will require approximately ten minutes to fully build the user profile and desktop environment. 

| ![Workstation Initial Login Process](img/linux-rdp-initial-ws-login.jpg) | 
|------------------------------------------------|

&#x21E8; *Step Complete, Go to the next step!*

</blockquote></details>



<Details><summary>

## &#x2462; Establish Remote Desktop Connections (from Windows) 

</summary><blockquote>

Establish RDP connections to the workstation and domain controller (Windows terminal services client)

The following screenshot includes an **example** mstsc connection string. *Your IP address will differ.*

| ![mstsc /v connection.string](img/win-mstsc-string.jpg) | 
|------------------------------------------------|

Be sure to include the domain on the initial RDP connections.

```Win-creds
doazlab\doadmin
DOLabAdmin1!
```

| ![Credential Offer to RDP Server](img/win-rdp-creds.jpg) | 
|------------------------------------------------|

Establish an RDP connection to the IP address of your lab's domain controller. You will be prompted to accept a certificate that should match **DC01.doazlab.com**.

| ![DC Cert Offer](img/win-rdp-cert-dc.jpg) | 
|------------------------------------------------|

Establish an RDP connection to the IP address of your lab's workstation. You will be prompted to accept a certificate that should match **WS05.doazlab.com**.

| ![WS Cert Offer](img/win-rdp-cert-ws.jpg) | 
|------------------------------------------------|

The domain controller will prompt you to accept the discovery settings. Your lab is isolated and our guidance is to click **Yes**. The course authors do not believe choosing **No** will affect any of the course content.

| ![DC Initial Desktop](img/win-rdp-initial-dc-desktop.jpg) | 
|------------------------------------------------|

The first login to the workstation will require approximately ten minutes to fully build the user profile and desktop environment. The desktop background includes bginfo.exe as a desktop background for quick reference as to which system you have accessed. 

| ![WS Initial Desktop](img/win-rdp-initial-ws-desktop.jpg) | 
|------------------------------------------------|

&#x21E8; *Step Complete, Go to the next step!*

</blockquote></details>



<Details><summary>

## &#x2463; Establish SSH Connection 

</summary><blockquote>

| &#x1F427; Bash Input | Linux Host: Nux01 |
|----------------------|-------------------|
```bash
ssh doadmin@'YOUR-PUB-C2-IP'
```

```Linux-creds
doadmin
DOLabAdmin1!
```

| ![Connection to SSH Server from Linux](img/linux-ssh-connect.jpg) | 
|------------------------------------------------|

Did you know you can SSH directly from Windows 10 without additional installation, packages, or software? You can, straight from PowerShell.

| &#x1FA9F; PowerShell Input |
|-----------------------|
```PowerShell
ssh doadmin@'YOUR-PUB-C2-IP'
```

| ![Connection to SSH Server from Windows PowerShell](img/win-ssh-connect.jpg) | 
|------------------------------------------------|

&#x21E8; *Step Complete, Go to the next step!*

</blockquote></details>

# Installing Tools Rapid Fire Style

We packed a bunch of tools onto your Linux system during the build process. So, there's a start, but here's some more quick hitters. We regularly wrap python tools in virtual environments, so be prepared to `activate` and `deactivate`. Also, install virtual-env. 

```
apt install python3-virtualenv -y 
```

Or, use pip. 

```
python3 -m pip install venv
```

Now, let's rock and roll. One of the tools we didn't install via bootstrap on the Linux box was DonPAPI. This is a browser shredder (and more). Copy and paste the following block into your Linux terminal. 

```
cd /opt/
git clone https://github.com/login-securite/DonPAPI
cd DonPAPI
virtualenv -p python3 dp-env
source dp-env/bin/activate
python3 -m pip install .
DonPAPI -h
```


# BadBlood



### &#x1FA9F; Windows credentials

When logging into the Windows system, use the following credentials.

```Win-creds
doazlab\doadmin
DOLabAdmin1!
```

## &#x2460; AD Pollution with BadBlood

</summary><blockquote>

_Conduct Lab Operations from Domain Controller DC01_

First, download and invoke BadBlood.

** This is dangerous DO NOT RUN IN PRODUCTION ** 

The following commands should be pasted into a PowerShell terminal session on the domain controller. 

| &#x1FA9F; PowerShell Input | Domain Controller: DC01 |
|----------------------------|-------------------------|
```PowerShell
$ProgressPreference = 'SilentlyContinue' 
invoke-webrequest -URI https://github.com/Relkci/BadBlood/archive/refs/heads/master.zip -outfile badblood.zip 
Expand-Archive .\badblood.zip 
$ProgressPreference = 'Continue' 
./badblood/BadBlood-master/invoke-badblood.ps1
```

| ![AD Pollution with BadBlood](img/ad-pollution-badblood-1.jpg) | 
|------------------------------------------------|

Three strikes against the enter key will result in a prompt to confirm your intentions. Again, *DO NOT RUN THIS IN PRODUCTION**. The `badblood` key word will then result in the creation of various AD objects, ACL tampering, and general pollution of your doazlab.com forest.

| &#x1FA9F; PowerShell Input | Domain Controller: DC01 |
|----------------------------|-------------------------|
```PowerShell
 [ENTER] x 3
 badblood
```

Some errors are expected. 

| ![AD Pollution Errors with BadBlood](img/ad-pollution-badblood-errors.jpg) | 
|------------------------------------------------|

**Exit PowerShell's AD> Prompt!**

| &#x1FA9F; PowerShell Input | Domain Controller: DC01 |
|----------------------------|-------------------------|
```PowerShell
exit
```

&#x21E8; *Step Complete, Go to the next step!*

</blockquote></details>



# GO SPEEDRACER GO!!!!!!


