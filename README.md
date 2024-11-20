# Deploy Next.js on AWS EC2

## Prerequisites

- AWS EC2 Instance: An Ubuntu server instance set up on AWS EC2.
- Domain Name: A registered domain name pointing to your EC2 instance.
- SSH Key Pair: Access to your EC2 instance via SSH using a key pair.
- GitHub Repository: Your Next.js application hosted on GitHub.

---

## GitHub Configuration

Go to your repository on GitHub and navigate to Settings > Secrets > Actions. Add the required secrets for deployment:
- **HOST**: Your EC2 instance public DNS.
- **KEY**: Your SSH private key.
- **USER**: Your EC2 instance username (default: ubuntu).
- **PORT**: Your EC2 instance SSH port (default: 22).

---

## AWS Configuration

Allocate an Elastic IP:  
- Go to the AWS Management Console.
- Navigate to the EC2 Dashboard.
- In the left-hand menu, click on "Elastic IPs".
- Click on the "Allocate Elastic IP address" button.

Associate the Elastic IP with your EC2 instance:  
- Select the newly allocated Elastic IP.
- Click on the "Actions" dropdown and select "Associate Elastic IP address".
- Choose your EC2 instance from the list and associate it.

---

## DNS Configuration

Create A Records:
- `your-domain.com` → EC2 Allocated IPv4 address
- `www.your-domain.com` → EC2 Allocated IPv4 address

---

## Linux Ubuntu Setup

### Connecting to the EC2 Instance via SSH

```bash
ssh -i /path/key-pair-name.pem instance-user-name@instance-public-dns-name
```

### System Update

```bash
sudo apt update
```

### Installing Node.js with Node Version Manager

[GitHub - Node Version Manager](https://github.com/nvm-sh/nvm)

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source ~/.bashrc
nvm install --lts
```

### Install pnpm

[Installation Guide](https://pnpm.io/installation)

```bash
curl -fsSL https://get.pnpm.io/install.sh | sh -
```

### Install PM2

```bash
pnpm install pm2@latest -g
```

### Setting Up GitHub SSH Access

```bash
# Create a new SSH key
ssh-keygen

# Copy SSH Key to GitHub: https://github.com/settings/keys
cat id_ed25519.pub

# Establishing a GitHub Connection
ssh git@github.com
```

### Set Up Application Directory

```bash
# Create a directory for application files.
sudo mkdir /var/www/app

# Change ownership of the directory to www-data.
sudo chown www-data:www-data /var/www/app

# Grant write permissions to the group for the directory.
sudo chmod -R 775 /var/www

# Add the current user to the www-data group.
sudo usermod -a -G www-data $USER
```

---

## Setup Nginx on Linux Ubuntu

[Nginx Documentation](https://nginx.org/en/docs/)

### Install Nginx

[How to Install Nginx | Ubuntu](https://ubuntu.com/server/docs/how-to-install-nginx)

```bash
sudo apt install nginx
```

### Configure Firewall

```bash
# Allow full Nginx access through the firewall
sudo ufw allow 'Nginx Full'
```

### Nginx Configuration

[How to configure Nginx | Ubuntu](https://ubuntu.com/server/docs/how-to-configure-nginx)

```bash
sudo nano /etc/nginx/sites-available/your-domain
```

Insert the following configuration and replace your-domain.com with your actual domain.:

```bash
upstream your-domain {
    server 127.0.0.1:3000;
    keepalive 64;
}

server {
    server_name your-domain.com www.your-domain.com;

    location / {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $http_host;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_pass http://your-domain/;
        proxy_redirect off;
        proxy_read_timeout 240s;
    }

        # Add security and behavior-defining headers

        # Prevents the website from being embedded in any iframe, even on the same origin.
        add_header X-Frame-Options "DENY";
        # Enables the browser’s built-in XSS filter and completely blocks the page.
        add_header X-XSS-Protection "1; mode=block";
        # Controls how much of the referrer information is sent when navigating from your site to another.
        add_header Referrer-Policy "strict-origin-when-cross-origin";
        # Ensures your site’s default content type is text/html and uses UTF-8 character encoding.
        default_type text/html;
        charset utf-8;
        # Allows cross-origin requests from the specified domain.
        add_header Access-Control-Allow-Origin "https://elfatuaki.com";
        # Enhances security by isolating your site from other cross-origin contexts.
        add_header Cross-Origin-Opener-Policy "same-origin";
        # Ensures that resources embedded in your site are loaded from the same origin or have proper CORS headers.
        add_header Cross-Origin-Embedder-Policy "require-corp";
        # Restricts resources like images or scripts to be loaded only from the same site.
        add_header Cross-Origin-Resource-Policy "same-site";
        # Limits access to sensitive APIs like geolocation, camera, or microphone.
        add_header Permissions-Policy "geolocation=(), camera=(), microphone=()";
        # Enforces the use of HTTPS and specifies a max age for the HSTS policy.
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        # Prevents MIME type sniffing, forcing browsers to use the declared Content-Type.
        add_header X-Content-Type-Options nosniff;

    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}

server {
    if ($host = www.your-domain.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot

    if ($host = your-domain.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot

    listen 80;

    server_name your-domain.com www.your-domain.com;
    return 404; # managed by Certbot
}
```

- Recommended Http Headers: [OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- Scan Security Headers: [Security Headers](https://securityheaders.com)

### Validate, Enable Configuration and Restart Nginx

```bash
# Validate configuration file.
sudo nginx -t

# Symlink the configuration file to the sites-enabled directory.
sudo ln -s /etc/nginx/sites-available/production /etc/nginx/sites-enabled

# Restart NGINX to apply the changes.
sudo systemctl restart nginx
```

### Securing Nginx with Let’s Encrypt

[Certbot Instructions](https://certbot.eff.org/instructions?ws=nginx&os=ubuntufocal)

```bash
# Installing snap on Ubuntu
sudo apt install snapd

# Remove certbot-auto and any Certbot OS packages
sudo apt-get remove certbot
sudo dnf remove certbot
sudo yum remove certbot

# Install Certbot
sudo snap install --classic certbot

# Prepare the Certbot command
sudo ln -s /snap/bin/certbot /usr/bin/certbot

# Get and install certificates
sudo certbot --nginx

# Test automatic renewal
sudo certbot renew --dry-run

# The command to renew certbot is installed in one of the following locations:
# - `/etc/crontab/`
# - `/etc/cron.*/*`
# - `systemctl list-timers`
```

### Restart Nginx

```bash
sudo systemctl restart nginx
```

