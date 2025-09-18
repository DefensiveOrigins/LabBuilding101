This repo was created for the gracious folks at Wild West Hackin' Fest, who picked us up, dusted us off and said "here's another chance guys, go get 'em!" ...and who gave us an opportunity to run a rapid fire workshop about lab building.

Anyway, here's the Defensive Origins crew builds labs!

### Welcome to Lab Building 101

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

### Building a Lab on Azure with ARM

### Connecting to Infrastructure 

### Installing Tools Rapid Fire Style

### BadBlood

### GO SPEEDRACER GO!!!!!!


