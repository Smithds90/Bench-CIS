#!/usr/bin/env bash

couch_tomcat_conf=$(find /etc/tomcat* -prune 2>/dev/null | head -n 1)

couch_catalina_base=$(cb=$(ps --no-headers o args p 4 $(pidof java) | grep '\-Dcatalina\.base' | sed -r "s/^.*-Dcatalina\.base=([^'\"\s]\S*|'.*?'|\".*?\").*/\1/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); if [ -z "$cb" ]; then if [ ! -z "$couch_tomcat_conf" ]; then p=$(grep -hoP "^\s*CATALINA_BASE=([^'\"\s]\S*|'.*?'|\".*?\")" /etc/*/* 2>/dev/null | head -n 1 | sed -r "s/^\s*CATALINA_BASE=//" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); if [[ "$p" =~ ^(.*)\$(.+)$ ]]; then cb="${BASH_REMATCH[1]}"$(grep "^${BASH_REMATCH[2]}=" $(grep -oP "^\s*CATALINA_BASE=([^'\"\s]\S*|'.*?'|\".*?\")" /etc/*/* 2>/dev/null | head -n 1 | awk -F: '{print $1}') | cut -d= -f2); else cb="$p"; fi; else cb=$(find / -type f -name catalina.jar | head -n 1 | sed 's#/lib/catalina\.jar##'); fi; fi; echo "$cb" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")

couch_catalina_home=$(ch=$(ps --no-headers o args p 4 $(pidof java) | grep '\-Dcatalina\.base' | sed -r "s/^.*-Dcatalina\.home=([^'\"\s]\S*|'.*?'|\".*?\").*/\1/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); if [ -z "$ch" ]; then if [ ! -z "$couch_tomcat_conf" ]; then p=$(grep -hoP "^\s*CATALINA_HOME=([^'\"\s]\S*|'.*?'|\".*?\")" /etc/*/* 2>/dev/null | head -n 1 | sed -r "s/^\s*CATALINA_HOME=//" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); if [[ "$p" =~ ^(.*)\$(.+)$ ]]; then ch="${BASH_REMATCH[1]}"$(grep "^${BASH_REMATCH[2]}=" $(grep -oP "^\s*CATALINA_HOME=([^'\"\s]\S*|'.*?'|\".*?\")" /etc/*/* 2>/dev/null | head -n 1 | awk -F: '{print $1}') | cut -d= -f2); else ch="$p"; fi; else ch=$(find / -type f -name catalina.jar | head -n 1 | sed 's#/lib/catalina\.jar##'); fi; fi; echo "$ch" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")

couch_tomcat_user=$(ps --no-headers o user:32,pid,comm,args p 4 $(pidof java) | grep '\-Dcatalina\.base' | awk '{print $1}')

couch_tomcat_group=$(id -gn $couch_tomcat_user)


echo "[Manual]" 'Leverage the package or services manager for your OS to uninstall or disable unneeded services.'
read -n 1 -p "Press Enter to continue..."


rm -r -f "$couch_catalina_base"/webapps/examples "$couch_catalina_base"/webapps/docs "$couch_catalina_base"/webapps/ROOT "$couch_catalina_base"/webapps/js-examples "$couch_catalina_base"/webapps/servlet-example "$couch_catalina_base"/webapps/webdav "$couch_catalina_base"/webapps/tomcat-docs "$couch_catalina_base"/webapps/balancer 2>/dev/null || true
read -p "Remove default manager and host-manager applications?[y][N]" c_change; if [[ "$c_change" == 'Y' || "$c_change" == 'y' ]]; then rm -r -f "$couch_catalina_base"/webapps/host-manager "$couch_catalina_base"/webapps/manager "$couch_catalina_base"/server/webapps/host-manager "$couch_catalina_base"/server/webapps/manager "$couch_catalina_base"/conf/Catalina/localhost/host-manager.xml "$couch_catalina_base"/conf/Catalina/localhost/manager.xml 2>/dev/null || true;
[[ -n "$couch_tomcat_conf" ]] && rm -f "$couch_tomcat_conf"/Catalina/localhost/host-manager.xml "$couch_tomcat_conf"/Catalina/localhost/manager.xml 2>/dev/null || true; fi


echo "[Manual]" 'Within $CATALINA_BASE/conf/server.xml, remove or comment each unused Connector. For example, to disable an instance of the HTTPConnector, remove the following:
<Connector className="org.apache.catalina.connector.http.HttpConnector" 
...                         
connectionTimeout="60000"/>

$CATALINA_BASE/conf/server.xml, has the following connectors defined by default:
• A non-SSL HTTP Connector bound to port 8080
• An AJP Connector bound to port 8009'
read -n 1 -p "Press Enter to continue..."


cd "$couch_catalina_home"/lib
jar xf catalina.jar org/apache/catalina/util/ServerInfo.properties && sed -i "s;\(server.info=\).*$;\1Nginx;g" org/apache/catalina/util/ServerInfo.properties && jar uf catalina.jar org/apache/catalina/util/ServerInfo.properties


cd "$couch_catalina_home"/lib
jar xf catalina.jar org/apache/catalina/util/ServerInfo.properties && sed -i "s;\(server.number=\).*$;\12;g" org/apache/catalina/util/ServerInfo.properties && jar uf catalina.jar org/apache/catalina/util/ServerInfo.properties


cd "$couch_catalina_home"/lib
jar xf catalina.jar org/apache/catalina/util/ServerInfo.properties && sed -i "s;\(server.built=\).*$;\1Night;g" org/apache/catalina/util/ServerInfo.properties && jar uf catalina.jar org/apache/catalina/util/ServerInfo.properties


if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's/xpowered[bB]y=".*"//g' | sed 's/<Connector\s/<Connector xpoweredBy="false" /g' >> "$couch_tomcat_conf"/server.xml.couch_tmp; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's/xpowered[bB]y=".*"//g' | sed 's/<Connector\s/<Connector xpoweredBy="false" /g' >> "$couch_catalina_base"/conf/server.xml.couch_tmp; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi

if [[ -n "$couch_tomcat_conf" ]];\
then i=0; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | egrep -i "^\s*<Connector" && i=1&&k=0; if [ "$i" == "1" ]; then echo "$line" | egrep -i "\sserver=" && k=1; if [ "$k" == 1 ]; then echo "$line" >> "$couch_tomcat_conf"/server.xml.couch_tmp; else echo "$line" | sed 's#/># server="serv1" />#' >> "$couch_tomcat_conf"/server.xml.couch_tmp; echo "$line" | egrep "/>" && i=0; fi; else echo "$line" >> "$couch_tomcat_conf"/server.xml.couch_tmp; fi; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else i=0; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | egrep -i "^\s*<Connector" && i=1&&k=0; if [ "$i" == "1" ]; then echo "$line" | egrep -i "\sserver=" && k=1; if [ "$k" == 1 ]; then echo "$line" >> "$couch_catalina_base"/conf/server.xml.couch_tmp; else echo "$line" | sed 's#/># server="serv1" />#' >> "$couch_catalina_base"/conf/server.xml.couch_tmp; echo "$line" | egrep "/>" && i=0; fi; else echo "$line" >> "$couch_catalina_base"/conf/server.xml.couch_tmp; fi; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi


if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | egrep -i "</web-app>" && (echo -e '<%@ page isErrorPage="true"%>\n\nOops! A 404 error happened because the resource could not be found.\n' >> "$couch_tomcat_conf"/error.jsp; echo -e "\t<error-page>\n\t\t<exception-type>java.lang.Throwable</exception-type>\n\t\t<location>"$couch_tomcat_conf"/error.jsp</location>\n\t</error-page>" >> "$couch_tomcat_conf"/web.xml.couch_tmp); echo "$line" >> "$couch_tomcat_conf"/web.xml.couch_tmp; done < "$couch_tomcat_conf"/web.xml; cp "$couch_tomcat_conf"/web.xml.couch_tmp "$couch_tomcat_conf"/web.xml; rm -f "$couch_tomcat_conf"/web.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/web.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | egrep -i "</web-app>" && (echo -e '<%@ page isErrorPage="true"%>\n\nOops! A 404 error happened because the resource could not be found.\n' >> "$couch_catalina_base"/conf/error.jsp; echo -e "\t<error-page>\n\t\t<exception-type>java.lang.Throwable</exception-type>\n\t\t<location>"$couch_catalina_base"/conf/error.jsp</location>\n\t</error-page>" >> "$couch_catalina_base"/conf/web.xml.couch_tmp); echo "$line" >> "$couch_catalina_base"/conf/web.xml.couch_tmp; done < "$couch_catalina_base"/conf/web.xml; cp "$couch_catalina_base"/conf/web.xml.couch_tmp "$couch_catalina_base"/conf/web.xml; rm -f "$couch_catalina_base"/conf/web.xml.couch_tmp;\
fi

for dir in `ls -d "$couch_catalina_base"/webapps/*`;\
do if [ -e "$dir/WEB-INF/web.xml" ];\
then rm -f "$dir"/WEB-INF/web.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | egrep -i "</web-app>" && (echo -e '<%@ page isErrorPage="true"%>\n\nOops! A 404 error happened because the resource could not be found.\n' >> "$dir"/WEB-INF/error.jsp; echo -e "\t<error-page>\n\t\t<exception-type>java.lang.Throwable</exception-type>\n\t\t<location>"$dir"/WEB-INF/error.jsp</location>\n\t</error-page>" >> "$dir"/WEB-INF/web.xml.couch_tmp); echo "$line" >> "$dir"/WEB-INF/web.xml.couch_tmp; done < "$dir"/WEB-INF/web.xml; cp "$dir"/WEB-INF/web.xml.couch_tmp "$dir"/WEB-INF/web.xml; rm -f "$dir"/WEB-INF/web.xml.couch_tmp;\
fi; done


if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)allow[tT]race=[^ />]*##g' | sed 's/<Connector\s/<Connector allowTrace="false" /g' >> "$couch_tomcat_conf"/server.xml.couch_tmp; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)allow[tT]race=[^ />]*##g' | sed 's/<Connector\s/<Connector allowTrace="false" /g' >> "$couch_catalina_base"/conf/server.xml.couch_tmp; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi

for dir in $(ls -d "$couch_catalina_base"/webapps/*);\
do grep -Ei '<web-resource-name>\s*restricted\s+methods\s*</web-resource-name>' "$dir"/WEB-INF/web.xml 2>/dev/null || echo -e "<security-constraint>\n<web-resource-collection>\n<web-resource-name>restricted methods</web-resource-name>\n<url-pattern>/*</url-pattern>\n<http-method>TRACE</http-method>\n</web-resource-collection>\n</security-constraint>" >> "$dir"/WEB-INF/web.xml;\
done


shutdown_code="$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 20)"
if [[ -n "$couch_tomcat_conf" ]];\
then i=0; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
while read -r line || [[ -n "$line" ]]; do echo "$line" | egrep -i "^\s*<Server" && i=1; if [ "$i" == "1" ]; then echo "$line" | sed 's#\(^\|\s\)shutdown=[^ />]*##g' | sed "s/<[sS]erver\s/<Server shutdown=\"${shutdown_code}\" /" >> "$couch_tomcat_conf"/server.xml.couch_tmp; echo "$line" | grep '>' && i=0; else echo "$line" >> "$couch_tomcat_conf"/server.xml.couch_tmp; fi; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else i=0; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
while read -r line || [[ -n "$line" ]]; do echo "$line" | egrep -i "^\s*<Server" && i=1; if [ "$i" == "1" ]; then echo "$line" | sed 's#\(^\|\s\)shutdown=[^ />]*##g' | sed "s/<[sS]erver\s/<Server shutdown=\"${shutdown_code}\" /" >> "$couch_catalina_base"/conf/server.xml.couch_tmp; echo "$line" | grep '>' && i=0; else echo "$line" >> "$couch_catalina_base"/conf/server.xml.couch_tmp; fi; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi


if [[ -n "$couch_tomcat_conf" ]];\
then i=0; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
while read -r line || [[ -n "$line" ]]; do echo "$line" | egrep -i "^\s*<Server" && i=1; if [ "$i" == "1" ]; then echo "$line" | sed 's#\(^\|\s\)port=[^ />]*##g' | sed 's/<[sS]erver\s/<Server port="-1" /' >> "$couch_tomcat_conf"/server.xml.couch_tmp; echo "$line" | grep '>' && i=0; else echo "$line" >> "$couch_tomcat_conf"/server.xml.couch_tmp; fi; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else i=0; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
while read -r line || [[ -n "$line" ]]; do echo "$line" | egrep -i "^\s*<Server" && i=1; if [ "$i" == "1" ]; then echo "$line" | sed 's#\(^\|\s\)port=[^ />]*##g' | sed 's/<[sS]erver\s/<Server port="-1" /' >> "$couch_catalina_base"/conf/server.xml.couch_tmp; echo "$line" | grep '>' && i=0; else echo "$line" >> "$couch_catalina_base"/conf/server.xml.couch_tmp; fi; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_home"; else echo "Tomcat admin user not detected"; fi
chmod g-w,o-rwx "$couch_catalina_home"


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"; else echo "Tomcat admin user not detected"; fi
 chmod g-w,o-rwx "$couch_catalina_base"


if [[ -n "$couch_tomcat_user" && -n "$couch_tomcat_group" ]]; then if [[ -n "$couch_tomcat_conf" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_tomcat_conf"; else chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"/conf; fi; else echo "Tomcat admin user not detected"; fi
if [[ -n "$couch_tomcat_conf" ]]; then chmod g-w,o-rwx "$couch_tomcat_conf"; else chmod g-w,o-rwx "$couch_catalina_base"/conf; fi


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"/logs; chown $couch_tomcat_user:$couch_tomcat_group /var/log/tomcat*; else echo "Tomcat admin user not detected"; fi
chmod o-rwx "$couch_catalina_base"/logs
chmod o-rwx /var/log/tomcat*


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"/temp; chown $couch_tomcat_user:$couch_tomcat_group /var/tmp/tomcat*; else echo "Tomcat admin user not detected"; fi
chmod o-rwx "$couch_catalina_base"/temp
chmod o-rwx /var/tmp/tomcat*


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_home"/bin; else echo "Tomcat admin user not detected"; fi
chmod g-w,o-rwx "$couch_catalina_home"/bin


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"/webapps; else echo "Tomcat admin user not detected"; fi
chmod g-w,o-rwx "$couch_catalina_base"/webapps


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then if [[ -n "$couch_tomcat_conf" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_tomcat_conf"/catalina.policy; else chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"/conf/catalina.policy; fi; else echo "Tomcat admin user not detected"; fi
if [[ -n "$couch_tomcat_conf" ]]; then chmod u-x,go-rwx "$couch_tomcat_conf"/catalina.policy; else chmod u-x,go-rwx "$couch_catalina_base"/conf/catalina.policy; fi


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then if [[ -n "$couch_tomcat_conf" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_tomcat_conf"/catalina.properties; else chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"/conf/catalina.properties; fi; fi
if [[ -n "$couch_tomcat_conf" ]]; then chmod u-x,go-rwx "$couch_tomcat_conf"/catalina.properties; else chmod u-x,go-rwx "$couch_catalina_base"/conf/catalina.properties; fi


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then if [[ -n "$couch_tomcat_conf" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_tomcat_conf"/context.xml; else chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"/conf/context.xml; fi; fi
if [[ -n "$couch_tomcat_conf" ]]; then chmod u-x,go-rwx "$couch_tomcat_conf"/context.xml; else chmod u-x,go-rwx "$couch_catalina_base"/conf/context.xml; fi


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then if [[ -n "$couch_tomcat_conf" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_tomcat_conf"/logging.properties; else chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"/conf/logging.properties; fi; fi
if [[ -n "$couch_tomcat_conf" ]]; then chmod u-x,go-rwx "$couch_tomcat_conf"/logging.properties; else chmod u-x,go-rwx "$couch_catalina_base"/conf/logging.properties; fi


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then if [[ -n "$couch_tomcat_conf" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_tomcat_conf"/server.xml; else chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"/conf/server.xml; fi; fi
if [[ -n "$couch_tomcat_conf" ]]; then chmod u-x,go-rwx "$couch_tomcat_conf"/server.xml; else chmod u-x,go-rwx "$couch_catalina_base"/conf/server.xml; fi


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then if [[ -n "$couch_tomcat_conf" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_tomcat_conf"/tomcat-users.xml; else chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"/conf/tomcat-users.xml; fi; fi
if [[ -n "$couch_tomcat_conf" ]]; then chmod u-x,go-rwx "$couch_tomcat_conf"/tomcat-users.xml; else chmod u-x,go-rwx "$couch_catalina_base"/conf/tomcat-users.xml; fi


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then if [[ -n "$couch_tomcat_conf" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_tomcat_conf"/web.xml; else chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"/conf/web.xml; fi; fi
if [[ -n "$couch_tomcat_conf" ]]; then chmod u-x,go-rwx "$couch_tomcat_conf"/web.xml; else chmod u-x,go-rwx "$couch_catalina_base"/conf/web.xml; fi


if [[ ! -z "$couch_tomcat_user" ]]; then chown $couch_tomcat_user "$couch_catalina_home"/bin/shutdown.sh; fi
chmod og-rwx "$couch_catalina_home"/bin/shutdown.sh


if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then if [[ -n "$couch_tomcat_conf" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$couch_tomcat_conf"/jaspic-providers.xml; else chown $couch_tomcat_user:$couch_tomcat_group "$couch_catalina_base"/conf/jaspic-providers.xml; fi; fi
if [[ -n "$couch_tomcat_conf" ]]; then chmod u-x,go-rwx "$couch_tomcat_conf"/jaspic-providers.xml; else chmod u-x,go-rwx "$couch_catalina_base"/conf/jaspic-providers.xml; fi


if [[ -n "$couch_tomcat_conf" ]];\
then i=0; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
while read -r line || [[ -n "$line" ]]; do echo "$line" | egrep -i "^\s*<Realm\s+.*className=.*(memoryrealm|jdbcrealm|userdatabaserealm|jaasrealm)" && i=1; if [ "$i" == "0" ]; then echo "$line" >> "$couch_tomcat_conf"/server.xml.couch_tmp; else echo "$line" | egrep -i '(</realm>|/>)' && i=0; fi; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else i=0; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
while read -r line || [[ -n "$line" ]]; do echo "$line" | egrep -i "^\s*<Realm\s+.*className=.*(memoryrealm|jdbcrealm|userdatabaserealm|jaasrealm)" && i=1; if [ "$i" == "0" ]; then echo "$line" >> "$couch_catalina_base"/conf/server.xml.couch_tmp; else echo "$line" | egrep -i '(</realm>|/>)' && i=0; fi; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi


echo "[Manual]" 'Create a lockout realm wrapping the main realm like the example below (file $CATALINA_BASE/conf/server.xml): 
<Realm className="org.apache.catalina.realm.LockOutRealm" failureCount="5" lockOutTime="7200" cacheSize="1000" cacheRemovalWarningTime="3600"> 
<Realm className="org.apache.catalina.realm.DataSourceRealm" dataSourceName=... /> 
</Realm>'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'In the Connector element set the clientAuth parameter to true, example:
<-- Define a SSL Coyote HTTP/1.1 Connector on port 8443 --> 
<Connector  
           port="8443" minProcessors="5" maxProcessors="75" 
           enableLookups="true" disableUploadTimeout="true" 
           acceptCount="100" debug="0" scheme="https" secure="true"; 
           clientAuth="true" sslProtocol="TLS"/>
In Tomcat 8.5 and 9 set the certificateVerification to required, example:
<SSLHostConfig
certificateVerification="required"
/>'
read -n 1 -p "Press Enter to continue..."


# add SSLEnabled="true" where scheme is set to https

if [[ -n "$couch_tomcat_conf" ]]; \
then i=0; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do \
if [[ -n $(echo "$line" | grep -Ei '<Connector(\s|$)') ]]; then i=1; rm -f /tmp/couch_temp_file; fi; 
if [ "$i" == "1" ]; then echo "$line" >> /tmp/couch_temp_file; else echo "$line" >> "$couch_tomcat_conf"/server.xml.couch_tmp; fi; 
if [[ "$i" == "1" && -n $(echo "$line" | grep -Ei '>') ]]; then i=0; if [[ -n $(grep -Ei 'scheme=(.)https\1' /tmp/couch_temp_file) ]]; then grep -Ei 'sslenabled=(.)true\1' /tmp/couch_temp_file || sed -ri 's/<Connector(\s|$)/<Connector SSLEnabled="true" /' /tmp/couch_temp_file; fi; cat /tmp/couch_temp_file >> "$couch_tomcat_conf"/server.xml.couch_tmp; rm -f /tmp/couch_temp_file; fi; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; 
else i=0; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do \
if [[ -n $(echo "$line" | grep -Ei '<Connector(\s|$)') ]]; then i=1; rm -f /tmp/couch_temp_file; fi;
if [ "$i" == "1" ]; then echo "$line" >> /tmp/couch_temp_file; else echo "$line" >> "$couch_catalina_base"/conf/server.xml.couch_tmp; fi;
if [[ "$i" == "1" && -n $(echo "$line" | grep -Ei '>') ]]; then i=0; if [[ -n $(grep -Ei 'scheme=(.)https\1' /tmp/couch_temp_file) ]]; then grep -Ei 'sslenabled=(.)true\1' /tmp/couch_temp_file || sed -ri 's/<Connector(\s|$)/<Connector SSLEnabled="true" /' /tmp/couch_temp_file; fi; cat /tmp/couch_temp_file >> "$couch_catalina_base"/conf/server.xml.couch_tmp; rm -f /tmp/couch_temp_file; fi; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; \
fi;


# If scheme is not set for connector -> set it to scheme="http" (because of default)

if [[ -n "$couch_tomcat_conf" ]]; \
then i=0; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do \
if [[ -n $(echo "$line" | grep -Ei '<Connector(\s|$)') ]]; then i=1; rm -f /tmp/couch_temp_file; fi; 
if [ "$i" == "1" ]; then echo "$line" >> /tmp/couch_temp_file; else echo "$line" >> "$couch_tomcat_conf"/server.xml.couch_tmp; fi; 
if [[ "$i" == "1" && -n $(echo "$line" | grep -Ei '>') ]]; then i=0; grep -Ei 'scheme=\S+' /tmp/couch_temp_file || sed -ri 's/<Connector(\s|$)/<Connector scheme="http" /' /tmp/couch_temp_file; cat /tmp/couch_temp_file >> "$couch_tomcat_conf"/server.xml.couch_tmp; rm -f /tmp/couch_temp_file; fi; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; 
else i=0; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do \
if [[ -n $(echo "$line" | grep -Ei '<Connector(\s|$)') ]]; then i=1; rm -f /tmp/couch_temp_file; fi;
if [ "$i" == "1" ]; then echo "$line" >> /tmp/couch_temp_file; else echo "$line" >> "$couch_catalina_base"/conf/server.xml.couch_tmp; fi;
if [[ "$i" == "1" && -n $(echo "$line" | grep -Ei '>') ]]; then i=0; grep -Ei 'scheme=\S+' /tmp/couch_temp_file || sed -ri 's/<Connector(\s|$)/<Connector scheme="http" /' /tmp/couch_temp_file; cat /tmp/couch_temp_file >> "$couch_catalina_base"/conf/server.xml.couch_tmp; rm -f /tmp/couch_temp_file; fi; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; \
fi;


# Remove all secure= AND
# If SSLEnabled="true" is set for connector -> set in it secure="true"


if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)secure=[^ />]*##g' | sed 's;SSLEnabled="true";SSLEnabled="true" secure="true";g' >> "$couch_tomcat_conf"/server.xml.couch_tmp; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)secure=[^ />]*##g' | sed 's;SSLEnabled="true";SSLEnabled="true" secure="true";g' >> "$couch_catalina_base"/conf/server.xml.couch_tmp; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi


if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)ssl[pP]rotocol=[^ />]*##g' | sed 's/ssl[eE]nabled[pP]rotocols="[^=>]*"//g' | sed 's;SSLEnabled="true";SSLEnabled="true" sslProtocol="TLS" sslEnabledProtocols="TLSv1.2,TLSv1.3";g' >> "$couch_tomcat_conf"/server.xml.couch_tmp; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)ssl[pP]rotocol=[^ />]*##g' | sed 's/ssl[eE]nabled[pP]rotocols="[^=>]*"//g' | sed 's;SSLEnabled="true";SSLEnabled="true" sslProtocol="TLS" sslEnabledProtocols="TLSv1.2,TLSv1.3";g' >> "$couch_catalina_base"/conf/server.xml.couch_tmp; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi


for each in `ls "$couch_catalina_base"/webapps`; do mkdir "$couch_catalina_base"/webapps/"$each"/WEB-INF; mkdir "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes; touch "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties; done


if [[ -n "$couch_tomcat_conf" ]]; then tfile="$couch_tomcat_conf"/logging.properties; else tfile="$couch_catalina_base"/conf/logging.properties; fi
[[ -z $(grep -Ei '^\s*handlers\s*=[^#]*org\.apache\.juli\.(Async)?FileHandler' "$tfile") ]] && ( if [[ -n $(grep -Ei '^\s*handlers\s*=' "$tfile") ]]; then sed -ri 's/(^\s*handlers\s*=)/\1org.apache.juli.FileHandler,/' "$tfile"; else echo "handlers=org.apache.juli.FileHandler,java.util.logging.ConsoleHandler" >> "$tfile"; fi); [[ -z $(grep -Ei '^\s*handlers\s*=[^#]*java\.util\.logging\.ConsoleHandler' "$tfile") ]] && sed -ri 's/(^\s*handlers\s*=)/\1java.util.logging.ConsoleHandler,/' "$tfile"; sed -ri 's;^(\s*org.apache.juli.(Async)?FileHandler.level=.*);## \1;' "$tfile"; grep -Ei '^\s*handlers\s*=[^#]*org\.apache\.juli\.FileHandler' "$tfile" && echo "org.apache.juli.FileHandler.level=FINER" >> "$tfile"; grep -Ei '^\s*handlers\s*=[^#]*org\.apache\.juli\.AsyncFileHandler' "$tfile" && echo "org.apache.juli.AsyncFileHandler.level=FINER" >> "$tfile"

for each in $(ls "$couch_catalina_base"/webapps); do tfile="$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties; [[ -z $(grep -Ei '^\s*handlers\s*=[^#]*org\.apache\.juli\.(Async)?FileHandler' "$tfile") ]] && ( if [[ -n $(grep -Ei '^\s*handlers\s*=' "$tfile") ]]; then sed -ri 's/(^\s*handlers\s*=)/\1org.apache.juli.FileHandler,/' "$tfile"; else echo "handlers=org.apache.juli.FileHandler,java.util.logging.ConsoleHandler" >> "$tfile"; fi); [[ -z $(grep -Ei '^\s*handlers\s*=[^#]*java\.util\.logging\.ConsoleHandler' "$tfile") ]] && sed -ri 's/(^\s*handlers\s*=)/\1java.util.logging.ConsoleHandler,/' "$tfile"; sed -ri 's;^(\s*org.apache.juli.(Async)?FileHandler.level=.*);## \1;' "$tfile"; grep -Ei '^\s*handlers\s*=[^#]*org\.apache\.juli\.FileHandler' "$tfile" && echo "org.apache.juli.FileHandler.level=FINER" >> "$tfile"; grep -Ei '^\s*handlers\s*=[^#]*org\.apache\.juli\.AsyncFileHandler' "$tfile" && echo "org.apache.juli.AsyncFileHandler.level=FINER" >> "$tfile"; done


for each in $(ls "$couch_catalina_base"/webapps); do mkdir "$couch_catalina_base"/webapps/"$each"/META-INF 2>/dev/null; touch "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml; t=$(egrep -i 'className="org.apache.catalina.valves.AccessLogValve"' "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml); if [[ -z "$t" ]]; then echo -e "<Valve className=\"org.apache.catalina.valves.AccessLogValve\" \n\tdirectory=\"$couch_catalina_base/logs/\" \n\tpattern=\"%h %t %H cookie:%{SESSIONID}c request:%{SESSIONID}r  %m %U %s %q %r\" \n/>" >> "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml; mkdir "$couch_catalina_base/logs" 2>/dev/null; fi; done


for each in $(ls "$couch_catalina_base"/webapps); do mkdir "$couch_catalina_base"/webapps/"$each"/META-INF 2>/dev/null; touch "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml; if [[ -z $(grep -Ei 'className="org.apache.catalina.valves.AccessLogValve"' "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml) ]]; then sed -ri "s#</[cC]ontext>#\n<Valve className=\"org.apache.catalina.valves.AccessLogValve\" \n\tdirectory=\"$couch_catalina_base/logs/\" \n\tpattern=\"%h %t %H cookie:%{SESSIONID}c request:%{SESSIONID}r  %m %U %s %q %r\" \n/>\n</Context>" "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml; mkdir "$couch_catalina_base/logs" 2>/dev/null; fi; done

[[ -z "$CATALINA_HOME" ]] && CATALINA_HOME="$couch_catalina_home";
[[ -z "$CATALINA_BASE" ]] && CATALINA_BASE="$couch_catalina_base";
for each in $(ls "$couch_catalina_base"/webapps); do i=0; while read -r line || [[ -n "$line" ]]; do echo "$line" | egrep -i "^\s*<Valve" 1>/dev/null && i=1; if [ "$i" == "1" ]; then c_dir=$(echo "$line" | grep -Ei '(^|\s)directory=' | sed -r "s;^(.*\s)?directory=(.)(.*)\2.*$;\3;"); if [[ -n "$c_dir" ]]; then c_dir="${c_dir/\$CATALINA_HOME/$CATALINA_HOME}"; c_dir="${c_dir/\$CATALINA_BASE/$CATALINA_BASE}"; [[ -n "$couch_tomcat_user" && -n "$couch_tomcat_group" ]] && chown $couch_tomcat_user:$couch_tomcat_group "$c_dir"; chmod o-rwx "$c_dir"; fi; echo "$line" | grep '>' 1>/dev/null && i=0; fi; done < "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml; done


for each in $(ls "$couch_catalina_base"/webapps); do mkdir "$couch_catalina_base"/webapps/"$each"/META-INF 2>/dev/null; touch "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml; t=$(grep -i 'className="org.apache.catalina.valves.AccessLogValve"' "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml); if [[ -z "$t" ]]; then echo -e "<Valve className=\"org.apache.catalina.valves.AccessLogValve\" \n\tdirectory=\"$couch_catalina_base/logs/\" \n\tpattern=\"%h %t %H cookie:%{SESSIONID}c request:%{SESSIONID}r  %m %U %s %q %r\" \n/>" >> "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml; mkdir "$couch_catalina_base/logs" 2>/dev/null; \
else i=0; rm -f "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml.couch_tmp; \
while read -r line || [[ -n "$line" ]]; do if [ "$i" == 0 ]; then echo "$line" >> "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml.couch_tmp; echo "$line" | grep -i 'className="org.apache.catalina.valves.AccessLogValve"' && i=1&& echo -e '\tpattern="%h %t %H cookie:%{SESSIONID}c request:%{SESSIONID}r  %m %U %s %q %r"' >> "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml.couch_tmp; else echo "$line" | sed 's;pattern=.*\s*;;g' >> "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml.couch_tmp; echo "$line" | egrep -i '(/>|</Valve>)' && i=0; fi; \
done < "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml; cp "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml.couch_tmp "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml; rm -f "$couch_catalina_base"/webapps/"$each"/META-INF/context.xml.couch_tmp; \
fi; \
done


ls "$couch_catalina_base"/webapps | while read -r each; do read -p "Enter application name for $each, default is $each:" t_app_name; t_app_name="${t_app_name:=$each}"; grep ^[^#] "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties | grep -Ei "org.apache.juli.(Async)?FileHandler.directory\s*=" || (read -p "Enter log location for $each application:" t_app_log; grep -Ei '^\s*handlers\s*=[^#]*org\.apache\.juli\.FileHandler' "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties && echo -e "$t_app_name.org.apache.juli.FileHandler.directory=$t_app_log" >> "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties && mkdir -p "$t_app_log"; grep -Ei '^\s*handlers\s*=[^#]*org\.apache\.juli\.AsyncFileHandler' "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties && echo -e "$t_app_name.org.apache.juli.AsyncFileHandler.directory=$t_app_log" >> "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties && mkdir -p "$t_app_log"); grep ^[^#] "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties | grep -Ei "org.apache.juli.(Async)?FileHandler.prefix\s*=" || ( grep -Ei '^\s*handlers\s*=[^#]*org\.apache\.juli\.FileHandler' "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties && echo "$t_app_name.org.apache.juli.FileHandler.prefix=$t_app_name" >> "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties; grep -Ei '^\s*handlers\s*=[^#]*org\.apache\.juli\.AsyncFileHandler' "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties && echo "$t_app_name.org.apache.juli.AsyncFileHandler.prefix=$t_app_name" >> "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties); log_loc=$(grep ^[^#] "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties | grep -Ei "org.apache.juli.(Async)?FileHandler.directory=" | cut -d= -f2); if [[ ! -z "$couch_tomcat_user" && ! -z "$couch_tomcat_group" ]]; then chown $couch_tomcat_user:$couch_tomcat_group "$log_loc"; chmod o-rwx "$log_loc"; else echo "Tomcat admin user not detected"; fi; done;


if [[ -n "$couch_tomcat_conf" ]];\
then sed -ri 's;^(\s*java.util.logging.(Async)?FileHandler.limit=.*\s*);## \1;' "$couch_tomcat_conf"/logging.properties; echo -e "\njava.util.logging.FileHandler.limit=800000" >> "$couch_tomcat_conf"/logging.properties;\
else sed -ri 's;^(\s*java.util.logging.(Async)?FileHandler.limit=.*\s*);## \1;g' "$couch_catalina_base"/conf/logging.properties; echo -e "\njava.util.logging.FileHandler.limit=800000" >> "$couch_catalina_base"/conf/logging.properties;\
fi
for each in $(ls "$couch_catalina_base"/webapps); do sed -ri 's;^(\s*java.util.logging.(Async)?FileHandler.limit=.*\s*);## \1;g' "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties; echo -e "\njava.util.logging.FileHandler.limit=800000" >> "$couch_catalina_base"/webapps/"$each"/WEB-INF/classes/logging.properties; done


if [[ -n "$couch_tomcat_conf" ]];\
then sed -i 's;package.access\s*=;# package.access =;g' "$couch_tomcat_conf"/catalina.properties; echo -e "package.access = sun.,org.apache.catalina.,org.apache.coyote.,org.apache.tomcat., org.apache.jasper." >> "$couch_tomcat_conf"/catalina.properties;\
else sed -i 's;package.access=;# package.access=;g' "$couch_catalina_base"/conf/catalina.properties; echo -e "package.access = sun.,org.apache.catalina.,org.apache.coyote.,org.apache.tomcat., org.apache.jasper." >> "$couch_catalina_base"/conf/catalina.properties;\
fi


echo "[Manual]" 'The security policies implemented by the Java SecurityManager are configured in the $CATALINA_BASE/conf/catalina.policy file. Once you have configured the catalina.policy file for use with a SecurityManager, Tomcat can be started with a SecurityManager in place by using the --security option: 
$ $CATALINA_HOME/bin/catalina.sh start -security'
read -n 1 -p "Press Enter to continue..."


if [[ -n "$couch_tomcat_conf" ]];\
then sed -i 's;autoDeploy="\w*";;g' "$couch_tomcat_conf"/server.xml; sed -i 's;<Host\s;<Host autoDeploy="false" ;g' "$couch_tomcat_conf"/server.xml;\
else sed -i 's;autoDeploy="\w*";;g' "$couch_catalina_base"/conf/server.xml; sed -i 's;<Host\s;<Host autoDeploy="false" ;g' "$couch_catalina_base"/conf/server.xml;\
fi


if [[ -n "$couch_tomcat_conf" ]];\
then sed -i 's;deployOnStartup="\w*";;g' "$couch_tomcat_conf"/server.xml; sed -i 's;<Host\s;<Host deployOnStartup="false" ;g' "$couch_tomcat_conf"/server.xml;\
else sed -i 's;deployOnStartup="\w*";;g' "$couch_catalina_base"/conf/server.xml; sed -i 's;<Host\s;<Host deployOnStartup="false" ;g' "$couch_catalina_base"/conf/server.xml;\
fi


echo "[Manual]" 'Run the start script without root privileges:
su - tomcat -c $CATALINA_HOME/bin/catalina.sh start'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Edit $CATALINA_BASE/conf/tomcat-users.xml file and change user names tomcat, admin, both and role1.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'For each user listed in tomcat-users.xml file, to run: $CATALINA_HOME/bin/digest.sh -a SHA password 
and change the password user to contain the new hash'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Move the web content files to a separate partition from the tomcat system files and update your configuration.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'In the Context of the host-manager application (default placed in $CATALINA_BASE/webapps/<enginename>/<hostname>/host-manager.xml or $CATALINA_BASE/webapps/host-manager/META-INF/context.xml) add the '\''<Valve '\'' line with permitted IP-addresses, example: 
<Context path="/manager" docBase="${catalina.home}/webapps/manager" debug="0" privileged="true"> 
    <Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127\.0\.0\.1"/> 
   ...
</Context> 
Add hosts, comma separated, which are allowed to access the admin application.

Note: The RemoteAddrValve property expects a regular expression, therefore periods and other regular expression meta-characters must be escaped.'
read -n 1 -p "Press Enter to continue..."


if [ -e "$couch_catalina_base"/webapps/manager/manager.xml ]; then \
i=0; rm -f "$couch_catalina_base"/webapps/manager/manager.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do case "$i" in 0)\
echo "$line" >> "$couch_catalina_base"/webapps/manager/manager.xml.couch_tmp; echo "$line" | egrep -i "<Context path=\"/manager\"" && i=1&& echo "$line" | grep ">" && i=2;;\
1) echo "$line" >> "$couch_catalina_base"/webapps/manager/manager.xml.couch_tmp; echo "$line" | grep ">" && i=2;;\
2) echo '<Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127\.0\.0\.1"/> ' >> "$couch_catalina_base"/webapps/manager/manager.xml.couch_tmp; echo "$line" >> "$couch_catalina_base"/webapps/manager/manager.xml.couch_tmp; i=0;;\
esac ; done < "$couch_catalina_base"/webapps/manager/manager.xml; cp "$couch_catalina_base"/webapps/manager/manager.xml.couch_tmp "$couch_catalina_base"/webapps/manager/manager.xml; rm -f "$couch_catalina_base"/webapps/manager/manager.xml.couch_tmp;\
fi


if [[ -d "$couch_catalina_base"/webapps/manager/WEB-INF ]]; then grep -iE '<transport-guarantee>CONFIDENTIAL' "$couch_catalina_base"/webapps/manager/WEB-INF/web.xml || echo -e "<security-constraint>\n\t<user-data-constraint>\n\t\t<transport-guarantee>CONFIDENTIAL</transport-guarantee>\n\t</user-data-constraint>\n</security-constraint>" >> "$couch_catalina_base"/webapps/manager/WEB-INF/web.xml; fi


for name in `ls "$couch_catalina_base"/webapps`; do if [ "$line" == "manager" ]; then t_manager_host=$line; fi; if [ "$line" == "host-manager" ]; then t_manager_host=$line; fi; done
if [ ! -z $t_manager_host ]; then read -p "Enter new hame for host-manager app:" $t_hm_new_name; for name in `ls "$couch_catalina_base"/webapps`; do if [ "$line" == "manager" ]; then t_manager_host=$line; fi; done; mv "$couch_catalina_base/webapps/$t_manager_host/manager.xml" "$couch_catalina_base/webapps/$t_manager_host/$t_hm_new_name.xml"; sed -i "s;docBase=\\\"\w*\\\";docBase=\"$couch_catalina_base/server/webapps/$t_hm_new_name\";" "$couch_catalina_base/webapps/$t_manager_host/$t_hm_new_name.xml"; mv "$CATALINA_BASE/webapps/$t_manager_host" "$CATALINA_BASE/webapps/$t_hm_new_name"; fi


echo "[Manual]" 'Start Tomcat with strict compliance enabled.  Add the following to your startup script:
-Dorg.apache.catalina.STRICT_SERVLET_COMPLIANCE=true'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Start Tomcat with RECYCLE_FACADES set to true. Add the following to your startup script:
-Dorg.apache.catalina.connector.RECYCLE_FACADES=true

The default value is false.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Start Tomcat with ALLOW_BACKSLASH set to false and ALLOW_ENCODED_SLASH set to false.  Add the following to your startup script:
-Dorg.apache.catalina.connector. CoyoteAdapter.ALLOW_BACKSLASH=false 
-Dorg.apache.tomcat.util.buf. UDecoder.ALLOW_ENCODED_SLASH=false

By default both parameters are set to false.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Start Tomcat with USE_CUSTOM_STATUS_MSG_IN_HEADER set to false.  Add the following to your startup script:
-Dorg.apache.coyote.USE_CUSTOM_STATUS_MSG_IN_HEADER=false

By default this is set to false.'
read -n 1 -p "Press Enter to continue..."


if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)connection[tT]imeout=[^ />]*##g' | sed 's/<Connector\s/<Connector connectionTimeout="60000" /g' >> "$couch_tomcat_conf"/server.xml.couch_tmp; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)connection[tT]imeout=[^ />]*##g' | sed 's/<Connector\s/<Connector connectionTimeout="60000" /g' >> "$couch_catalina_base"/conf/server.xml.couch_tmp; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi


if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)max[hH]ttp[hH]eaderSize=[^ />]*##g' | sed 's/<Connector\s/<Connector maxHttpHeaderSize="8192" /g' >> "$couch_tomcat_conf"/server.xml.couch_tmp; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)max[hH]ttp[hH]eaderSize=[^ />]*##g' | sed 's/<Connector\s/<Connector maxHttpHeaderSize="8192" /g' >> "$couch_catalina_base"/conf/server.xml.couch_tmp; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi


if [[ -n "$couch_tomcat_conf" ]];\
then grep -Ei '<transport-guarantee>\s*confidential' "$couch_tomcat_conf"/web.xml || echo -e "<security-constraint>\n\t<user-data-constraint>\n\t\t<transport-guarantee>CONFIDENTIAL</transport-guarantee>\n\t</user-data-constraint>\n</security-constraint>" >> "$couch_tomcat_conf"/web.xml;\
else grep -Ei '<transport-guarantee>\s*confidential' "$couch_catalina_base"/conf/web.xml || echo -e "<security-constraint>\n\t<user-data-constraint>\n\t\t<transport-guarantee>CONFIDENTIAL</transport-guarantee>\n\t</user-data-constraint>\n</security-constraint>" >> "$couch_catalina_base"/conf/web.xml;\
fi


if [[ -n "$couch_tomcat_conf" ]];\
then grep -Ei '<param-name>\s*listings\s*</param-name>\s*<param-value>\s*false\s*</param-value>' "$couch_tomcat_conf"/web.xml || echo -e "<param-name>listings</param-name> <param-value>false</param-value>" >> "$couch_tomcat_conf"/web.xml;\
else grep -Ei '<param-name>\s*listings\s*</param-name>\s*<param-value>\s*false\s*</param-value>' "$couch_catalina_base"/conf/web.xml || echo -e "<param-name>listings</param-name> <param-value>false</param-value>" >> "$couch_catalina_base"/conf/web.xml;\
fi


if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)allow[lL]inking=[^ />]*##g' | sed 's/<Context\s/<Context allowLinking="false" /g' >> "$couch_tomcat_conf"/server.xml.couch_tmp; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)allow[lL]inking=[^ />]*##g' | sed 's/<Context\s/<Context allowLinking="false" /g' >> "$couch_catalina_base"/conf/server.xml.couch_tmp; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi

if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/context.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)allow[lL]inking=[^ />]*##g' | sed 's/<Context\s/<Context allowLinking="false" /g' >> "$couch_tomcat_conf"/context.xml.couch_tmp; done < "$couch_tomcat_conf"/context.xml; cp "$couch_tomcat_conf"/context.xml.couch_tmp "$couch_tomcat_conf"/context.xml; rm -f "$couch_tomcat_conf"/context.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/context.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)allow[lL]inking=[^ />]*##g' | sed 's/<Context\s/<Context allowLinking="false" /g' >> "$couch_catalina_base"/conf/context.xml.couch_tmp; done < "$couch_catalina_base"/conf/context.xml; cp "$couch_catalina_base"/conf/context.xml.couch_tmp "$couch_catalina_base"/conf/context.xml; rm -f "$couch_catalina_base"/conf/context.xml.couch_tmp;\
fi

for dir in $(ls -d "$couch_catalina_base"/webapps/*);\
do rm -f "$dir"/META-INF/context.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)allow[lL]inking=[^ />]*##g' | sed 's/<Context\s/<Context allowLinking="false" /g' >> "$dir"/META-INF/context.xml.couch_tmp; done < "$dir"/META-INF/context.xml; cp "$dir"/META-INF/context.xml.couch_tmp "$dir"/META-INF/context.xml; rm -f "$dir"/META-INF/context.xml.couch_tmp; done


if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)privileged=[^ />]*##g' | sed 's/<Context\s/<Context privileged="false" /g' >> "$couch_tomcat_conf"/server.xml.couch_tmp; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)privileged=[^ />]*##g' | sed 's/<Context\s/<Context privileged="false" /g' >> "$couch_catalina_base"/conf/server.xml.couch_tmp; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi

if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/context.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)privileged=[^ />]*##g' | sed 's/<Context\s/<Context privileged="false" /g' >> "$couch_tomcat_conf"/context.xml.couch_tmp; done < "$couch_tomcat_conf"/context.xml; cp "$couch_tomcat_conf"/context.xml.couch_tmp "$couch_tomcat_conf"/context.xml; rm -f "$couch_tomcat_conf"/context.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/context.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)privileged=[^ />]*##g' | sed 's/<Context\s/<Context privileged="false" /g' >> "$couch_catalina_base"/conf/context.xml.couch_tmp; done < "$couch_catalina_base"/conf/context.xml; cp "$couch_catalina_base"/conf/context.xml.couch_tmp "$couch_catalina_base"/conf/context.xml; rm -f "$couch_catalina_base"/conf/context.xml.couch_tmp;\
fi

for dir in $(ls -d "$couch_catalina_base"/webapps/*);\
do rm -f "$dir"/META-INF/context.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)privileged=[^ />]*##g' | sed 's/<Context\s/<Context privileged="false" /g' >> "$dir"/META-INF/context.xml.couch_tmp; done < "$dir"/META-INF/context.xml; cp "$dir"/META-INF/context.xml.couch_tmp "$dir"/META-INF/context.xml; rm -f "$dir"/META-INF/context.xml.couch_tmp; done


if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)cross[cC]ontext=[^ />]*##g' | sed 's/<Context\s/<Context crossContext="false" /g' >> "$couch_tomcat_conf"/server.xml.couch_tmp; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)cross[cC]ontext=[^ />]*##g' | sed 's/<Context\s/<Context crossContext="false" /g' >> "$couch_catalina_base"/conf/server.xml.couch_tmp; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi

if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/context.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)cross[cC]ontext=[^ />]*##g' | sed 's/<Context\s/<Context crossContext="false" /g' >> "$couch_tomcat_conf"/context.xml.couch_tmp; done < "$couch_tomcat_conf"/context.xml; cp "$couch_tomcat_conf"/context.xml.couch_tmp "$couch_tomcat_conf"/context.xml; rm -f "$couch_tomcat_conf"/context.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/context.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)cross[cC]ontext=[^ />]*##g' | sed 's/<Context\s/<Context crossContext="false" /g' >> "$couch_catalina_base"/conf/context.xml.couch_tmp; done < "$couch_catalina_base"/conf/context.xml; cp "$couch_catalina_base"/conf/context.xml.couch_tmp "$couch_catalina_base"/conf/context.xml; rm -f "$couch_catalina_base"/conf/context.xml.couch_tmp;\
fi

for dir in $(ls -d "$couch_catalina_base"/webapps/*);\
do rm -f "$dir"/META-INF/context.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)cross[cC]ontext=[^ />]*##g' | sed 's/<Context\s/<Context crossContext="false" /g' >> "$dir"/META-INF/context.xml.couch_tmp; done < "$dir"/META-INF/context.xml; cp "$dir"/META-INF/context.xml.couch_tmp "$dir"/META-INF/context.xml; rm -f "$dir"/META-INF/context.xml.couch_tmp; done


if [[ -n "$couch_tomcat_conf" ]];\
then rm -f "$couch_tomcat_conf"/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)enable[lL]ookups=[^ />]*##g' | sed 's/<Connector\s/<Connector enableLookups="false" /g' >> "$couch_tomcat_conf"/server.xml.couch_tmp; done < "$couch_tomcat_conf"/server.xml; cp "$couch_tomcat_conf"/server.xml.couch_tmp "$couch_tomcat_conf"/server.xml; rm -f "$couch_tomcat_conf"/server.xml.couch_tmp;\
else rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)enable[lL]ookups=[^ />]*##g' | sed 's/<Connector\s/<Connector enableLookups="false" /g' >> "$couch_catalina_base"/conf/server.xml.couch_tmp; done < "$couch_catalina_base"/conf/server.xml; cp "$couch_catalina_base"/conf/server.xml.couch_tmp "$couch_catalina_base"/conf/server.xml; rm -f "$couch_catalina_base"/conf/server.xml.couch_tmp;\
fi


if [[ -n "$couch_tomcat_conf" ]];\
then sed -i 's#</Server>#\n<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener" />\n</Server>#' "$couch_tomcat_conf"/server.xml;\
else sed -i 's#</Server>#\n<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener" />\n</Server>#' "$couch_catalina_base"/conf/server.xml;\
fi


if [[ -n "$couch_tomcat_conf" ]];\
then sed -i 's#</Server>#\n<Listener className="org.apache.catalina.security.SecurityListener" checkedOsUsers="root" minimumUmask="0007" />\n</Server>#' "$couch_tomcat_conf"/server.xml;\
else sed -i 's#</Server>#\n<Listener className="org.apache.catalina.security.SecurityListener" checkedOsUsers="root" minimumUmask="0007" />\n</Server>#' "$couch_catalina_base"/conf/server.xml;\
fi
if [[ -e "$couch_catalina_home/bin/catalina.sh" ]]; then cp "$couch_catalina_home"/bin/catalina.sh "$couch_catalina_home"/bin/catalina.sh.back; sed -i 's;#JAVA_OPTS="$JAVA_OPTS -Dorg.apache.catalina.security.SecurityListener.UMASK=`umask`";JAVA_OPTS="$JAVA_OPTS -Dorg.apache.catalina.security.SecurityListener.UMASK=`umask`";' "$couch_catalina_home"/bin/catalina.sh; fi


for dir in `ls -d "$couch_catalina_base"/webapps/*`;\
do if [[ ! -e "$dir/WEB-INF/web.xml" ]]; then touch "$dir/WEB-INF/web.xml"; fi; rm -f "$dir"/WEB-INF/web.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)metadata-complete=[^ />]*##g' | sed 's/<web-app\s/<web-app metadata-complete="true" /g' >> "$dir"/WEB-INF/web.xml.couch_tmp; done < "$dir"/WEB-INF/web.xml; cp "$dir"/WEB-INF/web.xml.couch_tmp "$dir"/WEB-INF/web.xml; rm -f "$dir"/WEB-INF/web.xml.couch_tmp; egrep -i 'metadata-complete="true"' "$dir/WEB-INF/web.xml" || echo -e '<web-app metadata-complete="true">\n</web-app>' >> "$dir/WEB-INF/web.xml"; done

for dir in `ls -d "$couch_catalina_base"/webapps/*`;\
do if [[ ! -e "$dir/META-INF/context.xml" ]]; then touch "$dir/META-INF/context.xml"; fi; rm -f "$dir"/META-INF/context.xml.couch_tmp; while read -r line || [[ -n "$line" ]]; do echo "$line" | sed 's#\(^\|\s\)log[eE]ffective[wW]eb[xX]ml=[^ />]*##g' | sed 's/<Context\s/<Context logEffectiveWebXml="true" /g' >> "$dir"/META-INF/context.xml.couch_tmp; done < "$dir"/META-INF/context.xml; cp "$dir"/META-INF/context.xml.couch_tmp "$dir"/META-INF/context.xml; rm -f "$dir"/META-INF/context.xml.couch_tmp; egrep -i 'logEffectiveWebXml="true"' "$dir/META-INF/context.xml" || echo -e '<Context logEffectiveWebXml="true">\n</Context>' >> "$dir/META-INF/context.xml"; done



