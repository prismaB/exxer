#!/bin/bash

[ $UID = 0 ] || { echo "please run it as root privalages this script." ; exit 1 ; }

[ $(command -v curl) ] || { echo "please install the package: 'curl'" ; exit 1 ; }
[ $(command -v git) ] || { echo "please install the package: 'git'" ; exit 1 ; }
[ $(command -v pip3) ] || { echo "please install the package: 'pip3'" ; exit 1 ; }

case ${1} in
    [iI][nN][sS][tT][aA][lL][lL]|--[iI][nN][sS][tT][aA][lL][lL]|-[iI])
        echo "Getting subsystem.."
        mkdir -p /usr/share/exxer/anonimity /usr/share/exxer/
        echo "Copying triggers.."
        mv exploit/ /usr/share/exxer/
        git clone https://github.com/htrgouvea/nipe.git /usr/share/exxer/anonimity/nipe
        echo "Copying main trigger.."
        chmod +x exxer.py
        cp exxer.py /usr/bin/exxer && echo "Installation completed successfully." || { echo "Can not copied the main trigger please check your local files." ; rm -rf /usr/share/exxer ; exit 1 ; }
        echo "installing python modules"
        pip3 install impacket pyfiglet cowsay colorama self

    ;;
    [uU][nN][iI][nN][sS][tT][aA][lL][lL]|--[uU][nN][iI][nN][sS][tT][aA][lL][lL]|-[uU])
        [ -d /usr/share/exxer ] && rm -rf /usr/share/exxer
        [ -e /usr/bin/exxer ] && rm /usr/bin/exxer
        echo "uninstall completed and depends not removed."
    ;;
    [rR][eE][iI][nN][sS][tT][aA][lL][lL]|--[rR][eE][iI][nN][sS][tT][aA][lL][lL]|-[rR])
        [ -d /usr/share/exxer ] && rm -rf /usr/share/exxer
        [ -e /usr/bin/exxer ] && rm /usr/bin/exxer
        echo "Getting subsystem.."
        mkdir -p /usr/share/exxer/anonimity /usr/share/exxer/
        echo "Copying triggers.."
        mv exploit/ /usr/share/exxer/
        git clone https://github.com/htrgouvea/nipe.git /usr/share/exxer/anonimity/nipe
        echo "Copying main trigger.."
        chmod +x exxer.py
        cp exxer.py /usr/bin/exxer && echo "Installation completed successfully." || { echo "Can not copied the main trigger please check your local files." ; rm -rf /usr/share/exxer ; exit 1 ; }
        echo "installing python modules"
        pip3 install impacket pyfiglet cowsay colorama self
        cp main.py /usr/bin/exxer && echo "Installation completed successfully." || { echo "Can not copied the main trigger please check your local files." ; rm -rf /usr/share/exxer ; exit 1 ; }
        pip3 install impacket pyfiglet cowsay colorama
    ;;
    *)
        echo -e "Unknow option. Correct flags are:\nbash ./${0}--install: install the script and dependences\nbash ./${0}--uninstall: uninstall the script so remove the local script's local files on your system.\nbash ./${0}--reinstall:\n before uninstall the script's local files if exist then install again."
        exit 1
    ;;
esac
