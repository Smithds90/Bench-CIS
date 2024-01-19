#!/usr/bin/env bash


echo "[Manual]" 'Ensure that the maintained version is in use and install its latest minor version. It can be download at https://www.keycloak.org/downloads'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Assign the host to the Keycloak and do not run other software and services with extraneous for Keycloak functionality on it. Minimize any access to the Keycloak host.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Development mode is not suitable for production usage. Do not run production instances of Keycloack in development mode.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Create and configure dedicated account to run Keycloak. It must have read access for Keycloak files and directories including the SLL/TLS private key, and write access to the Keycloak data directory and log file (if exist).'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Get the Keycloack account name used to run it:
ps --no-headers o user,args p $(pidof java) | grep '\''io\.quarkus\.bootstrap\.runner\.QuarkusEntryPoint'\''
Lock the Keycloak account password:
passwd -l <keycloak_account>'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Prevent providing the database password in the Keycloak command line options'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Prevent providing the "https-key-store-password" and "https-trust-store-password" params in the Keycloak command line options.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If there are any world-writable files or directories in the Keycloak home directory, revoke such access:
chmod o-w <filename>
It may be necessary to investigate how these access rights came about.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If there is some unnecessary group-write access to files or directories in the Keycloak home directory, revoke such access:
chmod g-w <filename>'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Revoke world-reading permission on the Keycloak confguration file:
chmod o-r <configuration_file_path>'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Check files from "https-certificate-key-file" and "https-key-store-file" configuration parameters and revoke any world access and group write access to them.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Revoke any world access permissions to the log file (if logging to file is configured).'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If there are some kcadm.config files with access permissions for group or/and other, then revoke these excessive permissions.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Do not enable HTTP for Keycloak in the production mode.

Note: An exception may be the configuration with access to the Keycloak via the reverse-proxy in the "edge" mode. But for environments with high security requirements this configuration is not recommended.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Ensure that only modern TLS protocols (TLS 1.2, TLS 1.3) are configured with the "https-protocols" configuration parameter.

Default: TLSv1.3.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Hostname (the "hostname" parameter) configuration is required for the Keycloak production mode.
Do not set the "hostname-strict" parameter to false.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'The best way to restrict access to administrative web interface is by using a reverse proxy and exposing only certain paths (they are listed on the Keycloak documentation page: https://www.keycloak.org/server/reverseproxy).
Another way is to hide administrative interface by binding it to another hostname. Configure the "hostname-admin" parameter to achieve this. It can be used without a reverse proxy or with it.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Configure usage at least one of file and gelf logging handlers with the "log" Keycloak configuration parameter. Specify additional configuration parameters for the selected logging method if needed, more information on https://www.keycloak.org/server/logging.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Configure the root log level in the "log-level" configuration parameter to INFO or more thorough level.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'The logging file should be placed on special partition separate from the Keycloak working files. If the file logging handler is in use, configure the "log-file" parameter to file location outside of the Keycloak home directory, the system partition and other sensitive partitions.

Default: data/log/keycloak.log.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Default file log format is '\''%d{yyyy-MM-dd HH:mm:ss,SSS} %-5p [%c] (%t) %s%e%n'\'' and contain all significant symbols. You can leave the default log format or configure custom which should contain the following symbols (at least): %c, %d, %e, %s (or %m), %p.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If gelf logging handler is in use, configure the logs sending to a centralized log system with the "log-gelf-host" parameter.
If only file logging handler is active, use some external for Keycloak tool to collect logs from the log file and send them to a centralized log system. For example, rsyslog may be used.'
read -n 1 -p "Press Enter to continue..."



