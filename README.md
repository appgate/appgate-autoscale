# Disclaimer
© 2019, AppGate.  All rights reserved.
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met: (a) redistributions
of source code must retain the above copyright notice, this list of conditions and
the disclaimer below, and (b) redistributions in binary form must reproduce the
above copyright notice, this list of conditions and the disclaimer below in the
documentation and/or other materials provided with the distribution.
THE CODE AND SCRIPTS POSTED ON THIS WEBSITE ARE PROVIDED ON AN “AS IS” BASIS AND
YOUR USE OF SUCH CODE AND/OR SCRIPTS IS AT YOUR OWN RISK.  APPGATE DISCLAIMS ALL
EXPRESS AND IMPLIED WARRANTIES, EITHER IN FACT OR BY OPERATION OF LAW, STATUTORY
OR OTHERWISE, INCLUDING, BUT NOT LIMITED TO, ALL WARRANTIES OF MERCHANTABILITY,
TITLE, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, ACCURACY, COMPLETENESS,
COMPATABILITY OF SOFTWARE OR EQUIPMENT OR ANY RESULTS TO BE ACHIEVED THEREFROM.
APPGATE DOES NOT WARRANT THAT SUCH CODE AND/OR SCRIPTS ARE OR WILL BE ERROR-FREE.
IN NO EVENT SHALL APPGATE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
RELIANCE, EXEMPLARY, PUNITIVE OR CONSEQUENTIAL DAMAGES, OR ANY LOSS OF GOODWILL,
LOSS OF ANTICIPATED SAVINGS, COST OF PURCHASING REPLACEMENT SERVICES, LOSS OF PROFITS,
REVENUE, DATA OR DATA USE, ARISING IN ANY WAY OUT OF THE USE AND/OR REDISTRIBUTION OF
SUCH CODE AND/OR SCRIPTS, REGARDLESS OF THE LEGAL THEORY UNDER WHICH SUCH LIABILITY
IS ASSERTED AND REGARDLESS OF WHETHER APPGATE HAS BEEN ADVISED OF THE POSSIBILITY
OF SUCH LIABILITY.

# Overview

All major cloud platforms provide means of auto-scaling instances using configurable policies.
It is possible to create a fully auto-scaled deployment of AppGate Gateways on any given site using the features described here.

For example, we can configure a site to auto-scale gateways based on memory or CPU usage.
It is also possible to use auto-scaling to just aid in automating deployment of gateways with a fixed number of gateways per site.

#### AWS
AWS provides a feature called auto-scaling groups to automatically increase or decrease the amount of instances running based on some metrics such as CPU or memory load.

See https://docs.aws.amazon.com/autoscaling/ec2/userguide/what-is-amazon-ec2-auto-scaling.html

#### GCP
GCP provides a feature called instance groups to automatically increase or decrease the amount of instances running based on some metrics such as CPU or memory load.

See https://cloud.google.com/compute/docs/instance-groups/

#### Azure
Azure provides a feature called virtual machine scale sets to automatically increase or decrease the amount of instances running based on some metrics such as CPU or memory load.

See https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/overview


## Before you start

To perform auto-scaling there are a number of things that have to be configured in AppGate SDP first.

#### Configure the auto-scale Appliance
For any given Site, a auto-scale appliance needs to be specified which will become a basic template and then vary only parameters such as hostname.
Create a new appliance tied to the specific Site. Configure it with all correct settings except a use bogus hostnames such as: template-gateway.example.com.
Assign a tag such as: siteX-autoscaling-template to the appliance, which will be used restrict admin access to only the templated and auto-scaled appliances.
NOTE: **Do not** activate the appliance. This configuration will be used as a template and it is the new instances created by the template that will end up being activated.

#### Configure the auto-scale admin user

While it is possible to use a regular admin user for auto-scaling,
it is highly recommended to create a separate admin user with limited rights.
Create an admin user called siteX-autoscaling, for example in the local identity provider.
Set a strong password, preferably randomly generated.
Exempt that user from MFA from the MFA for Admin settings page.

#### Configure the auto-scale admin role

The auto-scaling script needs rights to view the template appliance for the given site,
create a new appliance and export it's seed configuration.

We will create an role called siteX-autoscaling.
And add the following privileges:
- View appliances tagged with siteX-autoscaling-template and siteX-autoscaling-instance
- Create appliances with tag siteX-autoscaling-instance
- Export appliances with tag siteX-autoscaling-instance
- Delete appliances with tag siteX-autoscaling-instance (For down-scaling)

#### Configure the auto-scale Policy

Create a new policy for that user and assign it the siteX-autoscaling role.
For the policy assignment add the following two criteria:
- Identity Provider is the identity provider used for for the siteX-autoscaling user
- username is siteX-autoscaling

## Auto-Scaling Implementation

To automate auto-scaling we take advantage of the fact that we can pass a startup script to the appgate instance using the cloud provider's API.
This script will create an appliance configuration based on a template for the newly started instance and use it to seed itself.

Since we can only pass a single base64 blob as a parameter, the passed script needs to contain all the necessary parameters to create
an appliance and export the seed configuration, that is:
- The controller admin hostname or ip.
- The controller admin port. By default, 8443 if the admin interface is configured, else 444 if using the peer interface.
- The controller CA certificate.
  This is not necessary if the controller is configured to use the admin interface with a valid, non self-signed, certificate.
- The auto-scaling admin username and password.
- The site id.

The site id is visible in the URL when navigating to a site on the admin UI.
For example, given the site URL https://controller.example.com:444/ui/sites/edit/750f210a-1c42-4d27-b568-4a8767ef2790, the site id is 750f210a-1c42-4d27-b568-4a8767ef2790.

#### Appliance Template

Since we want all our Gateways to share a basic template and vary only parameters such as hostname, we need to create a new appliance which is assigned to our target Site.
This should be configured with all the necessary settings except that bogus hostnames should be used such as template-gateway.example.com. However, **do not** activate it.
This configuration will be used as a template when creating new instances.

To ensure the template appliance configuration gets used when there are several inactive appliances on the Site, add the template tag to it.
A Gateway with the `template` tag will always be used first.

#### Cloud Template and Startup Script

The way to make an auto-scaling group on your cloud provider an AppGate SDP Gateway auto-scaling group is to pass an auto-scaling startup script
containing your specific parameters as a startup script.

We use the following mechanisms on the different cloud platforms:
 - AWS: Using instance userdata. See https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html
 - GCP: Using virtual machine startup script. See https://cloud.google.com/compute/docs/startupscript
 - Azure: CustomData. See https://docs.microsoft.com/en-us/azure/virtual-machines/linux/using-cloud-init#deploying-a-cloud-init-enabled-virtual-machine

 Note that we expect the whole startup script to be passed as a startup script and not for example a cloud init configuration file.
 It is possible to create that script manually based on examples (see the Example section at the end).

 However to make the task slightly more convenient we provide a bootstrap command to generate a suitable script.
 The generated script can then be customized if necessary, for example to integrate with a credentials manager.

#### Bootstrapping

Use the script called appgate-autoscale.py to generate a startup script with all your parameters. This script requires python3.

For example:

    # Run the bootstrap script and use the resulting script as your launch configuration userdata.
    python3 appgate-autoscale.py bootstrap --hostname controller.example.com --port 8443 --username autoscale-admin-site1 --site 750f210a-1c42-4d27-b568-4a8767ef2790 --cacert mycacert.pem --password myautoscaleadminpassword --no-base64-encode --file my_example_upscale_script.py

The Python 3 binary is called python.exe, python on MacOS and python3 on linux.

#### Up-Scaling

If you have setup your instance group correctly with your start script it will be executed on appliance startup and perform up-scaling.
The instance will find the appliance template for it's site as defined on the controller and create a new appliance configuration based on it.
It will then export the configuration and seed itself.

The template is selected among the gateways in the given site.
Inactive appliances tagged with `template` are chosen in priority as the appliance template.

#### Down-Scaling

The bootstrap script will also setup the appliance for down-scaling by creating a shutdown script.
When the instance is shutdown it will delete its entry on the controller.

It is possible to disable this feature by passing the `--no-downscale-script` option to the bootstrap command.

#### Sharing the Client Hostname

By default the script will create an appliance configuration using the same hostname for the client hostname as for the peer hostname.
If you want it to use the client hostname from the template gateway configuration you can pass the `--share-client-hostname` option.

This is especially useful if you have configured your auto-scaling group to use a load balancer.

#### Peer Hostname Conflicts

If a gateway with the same peer hostname already exists in the site, the entry will be deleted by the autoscale script.
If the gateway is already activated to the controller the autoscale script will exit and do nothing.

#### Where to find appgate-autoscale.py

The gateway auto-scaling script is available for download from the admin UI by navigating to:
    
    Settings > Utilities > Gateway Auto-Scale Script

It is also available for download directly at:

    https://controller.example.com:444/appliance/autoscale-script

#### How to get the Controller CA Certificate

Go to your controller's admin UI and download the ca certificate in PEM form by navigating to:

    Settings > CA > Current CA > Download

It is also available for download directly at:

    https://controller.example.com:444/ui/global-settings/ca/pem

## Upgrading Auto-Scaling Gateways

When using auto-scaling, gateways should not be upgraded in place.
Instead new gateways can be created directly using the new version.

If you are using the upgrade script to upgrade your other appliances you can use the exclude
flag to skip the auto-scaling sites. For example:

    python3 appgate-upgrade.pyz install --exclude site=750f210a-1c42-4d27-b568-4a8767ef2790 ...

When an new AppGate SDP version is out a new image will be available for your cloud platform.
Point the auto-scaling group to that new image and then terminate the gateway instances running the old version one by one.
They will be replaced automatically by gateway instances running the new version.

#### AWS

On AWS this is done by creating a new launch configuration pointing to the new AMI and updating the auto-scaling group
to point to the new launch configuration.

## Advanced Setups

While the bootstrap script is convenient, it is also possible to create the entire auto-scaling script
for your site manually. Here are some examples that can be used as templates for your own setup.


#### Setup using a valid controller certificate and an external credentials manager

This example uses a fake credentials manager similar to HashiCorp's Vault.

This concept works for other providers like AWS Security Token Service (STS).
The controller is configured using with the admin interface enabled on port 8443 and a valid certificate.

```bash
#!/bin/sh

# Create a script that outputs the password for the auto-scaling admin user.
# The password is fetched dynamically every time it is needed to not expose credentials unnecessarily.
cat >/tmp/password-executable <<EOL
#!/usr/bin/python3
import json
import requests
r = requests.get('http://my-credential-manager.example.com/my-atuoscaling-secret', params={'token': 'ASDL...ASZSD'})
password = r.json()['data']['password']
print(json.dumps({"password": password}))
EOL
chmod +x /tmp/password-executable

# Seed this appliance.
# We can skip the --cacert parameter since we are using a valid public certificate on the admin interface.
python3 /usr/share/admin-scripts/appgate-autoscale.py upscale controller.example.com --port 8443 --username siteAWS-autoscaling --password-path /tmp/password-executable --site af4fedf3-5cc2-43fb-aff7-61b67369a505 --file /home/cz/seed.json

# Setup appliance to delete itself on shutdown
cat >/var/cache/cz-scripts/shutdown-script<<EOL
#!/bin/sh
/usr/share/admin-scripts/appgate-autoscale.py downscale controller.example.com --port 8443 --username siteAWS-autoscaling --password-path /tmp/password-executable
EOL
```

#### Setup using self-signed controller certificate using peer interface port 444

This example uses a standard setup with the controller using the peer interface on port 444 using it's self signed certificate.

The password is hardcoded in the startup script, which is **not recommended** in practice.

```bash
#!/bin/sh

# Add your Controller's CA certificate.
# This is not necessary if you are using a valid public certificate on the admin interface.
cat >/tmp/cacert.pem <<EOF
-----BEGIN CERTIFICATE-----
MIIFPDCCAySgAwIBAgIJAKJah5YABq/ZMA0GCSqGSIb3DQEBDQUAMBkxFzAVBgNV
BAMTDkFwcEdhdGUgWERQIENBMB4XDTE3MDIyNDE1MTExOVoXDTI3MDIyMjE1MTEx
[...]
zVAmFQL0rHwjonLsbLGBG54idCNTctN6HisBSdRmd7UlVdrABrbiBj42vQ7H8mwU
5qvvc4QH0X+dwU+QWVW0w+MDQNc+9xkTGTKaEiAiQ8WqigT88xUgTVEbSv25f9fm
-----END CERTIFICATE-----
EOF

# Create a script that outputs the password for the auto-scaling admin user
# In production, this should be getting the password from the appropriate credentials manager, for example STS on AWS.
cat >/tmp/password-executable <<EOL
#!/bin/sh
echo '{"password": "password_for_the_autoscaling_admin_user"}'
EOL
chmod +x /tmp/password-executable

# Seed this appliance
# Use the appropriate port, for example if you are using the admin interface on port 8443 pass --port 8443
# Skip the --cacert parameter if using a valid public certificate on the admin interface
python3 /usr/share/admin-scripts/appgate-autoscale.py upscale controller.example.com --port 444 --cacert /tmp/cacert.pem --username siteAWS-autoscaling --password-path /tmp/password-executable --site af4fedf3-5cc2-43fb-aff7-61b67369a505 --file /home/cz/seed.json

# Setup appliance to delete itself on shutdown
cat >/var/cache/cz-scripts/shutdown-script<<EOL
#!/bin/sh
/usr/share/admin-scripts/appgate-autoscale.py downscale controller.example.com --port 444 --cacert /tmp/cacert.pem --username siteAWS-autoscaling --password-path /tmp/password-executable
EOL
```
