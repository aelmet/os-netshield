PLUGIN_NAME=        netshield
PLUGIN_VERSION=     1.0
PLUGIN_REVISION=    0
PLUGIN_COMMENT=     Network security suite with app identification, device policies, DNS filtering, and VPN detection
PLUGIN_MAINTAINER=  netshield@community.dev
PLUGIN_WWW=         https://github.com/netshield-community/os-netshield
PLUGIN_DEPENDS=     python3 suricata
PLUGIN_LICENSE=     BSD2CLAUSE

.include "../../Mk/plugins.mk"
