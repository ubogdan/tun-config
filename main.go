package main

import (
	"bytes"
	"flag"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// compareIPNet return true if both IPNet are the same
func compareIPNet(a, b *net.IPNet) bool {
	if !a.IP.Equal(b.IP) {
		return false
	}
	if bytes.Compare([]byte(a.Mask), []byte(b.Mask)) != 0 {
		return false
	}
	return true
}

// enforceIPNet make sure only specified addresses are on link
func enforceIPNet(link netlink.Link, expected []*net.IPNet, family int, log *zap.Logger) error {
	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		return errors.Wrap(err, "netlink.AddrList")
	}

	var isChanged bool
	for ia := range addrs {
		var addrExpected bool
		for ie := range expected {
			if compareIPNet(addrs[ia].IPNet, expected[ie]) {
				addrExpected = true
			}
		}
		if !addrExpected {
			log.Debug("Unexpected address, remove", zap.String("unexpected", addrs[ia].IPNet.String()))
			if err = netlink.AddrDel(link, &addrs[ia]); err != nil {
				return errors.Wrapf(err, "netlink.AddrDel %q", addrs[ia].IPNet.String())
			}
			isChanged = true
		} else {
			log.Debug("Expected address, leave", zap.String("expected", addrs[ia].IPNet.String()))
		}
	}

	if isChanged {
		log.Debug("Refresh list of addresses")
		if addrs, err = netlink.AddrList(link, family); err != nil {
			return errors.Wrap(err, "netlink.AddrList")
		}
	}

	for ie := range expected {
		var exists bool
		for ia := range addrs {
			if compareIPNet(addrs[ia].IPNet, expected[ie]) {
				exists = true
			}
		}
		if !exists {
			log.Debug("Address not configured, add", zap.String("missing", expected[ie].String()))
			if err = netlink.AddrAdd(link, &netlink.Addr{
				IPNet: expected[ie],
			}); err != nil {
				return errors.Wrapf(err, "netlink.AddrAdd %q", expected[ie].String())
			}
		}
	}

	return nil
}

func enforceRoutes(link netlink.Link, expected []*net.IPNet, gw net.IP, family int, log *zap.Logger) error {
	routes, err := netlink.RouteList(link, family)
	if err != nil {
		return errors.Wrap(err, "netlink.RouteList")
	}

	var isChanged bool
	for ra := range routes {
		var (
			routeExpected bool
			fields        = routeFields(routes[ra])
		)
		if routes[ra].Gw == nil {
			log.Debug("Skip link route", fields...)
			continue
		}
		if routes[ra].Dst == nil {
			log.Debug("Skip default route", fields...)
			continue
		}

		for re := range expected {
			if compareIPNet(routes[ra].Dst, expected[re]) && routes[ra].Gw.Equal(gw) {
				routeExpected = true
			}
		}
		if !routeExpected {
			log.With(fields...).Debug("Unexpected route, remove", zap.String("unexpected", routes[ra].Gw.String()))
			if err = netlink.RouteDel(&routes[ra]); err != nil {
				return errors.Wrapf(err, "netlink.RouteDel %q", routes[ra].Gw.String())
			}
			isChanged = true
		} else {
			log.With(fields...).Debug("Expected route, leave", zap.String("expected", routes[ra].Gw.String()))
		}
	}

	if isChanged {
		log.Debug("Refresh list of routes")
		if routes, err = netlink.RouteList(link, family); err != nil {
			return errors.Wrap(err, "netlink.RouteList")
		}
	}

	for re := range expected {
		var exists bool
		l := log.With(zap.String("expected", expected[re].String()))

		for ra := range routes {
			fields := routeFields(routes[ra])

			if routes[ra].Gw == nil {
				l.Debug("Skip link route", fields...)
				continue
			}

			if routes[ra].Dst == nil {
				l.Debug("Skip default route", fields...)
				continue
			}

			if compareIPNet(routes[ra].Dst, expected[re]) {
				l.Debug("Route already exists", fields...)
				exists = true
				continue
			}

			l.Debug("Missing route", fields...)
		}
		if !exists {
			l.Debug("Routes not configured, add", zap.String("missing", expected[re].String()))
			if err = netlink.RouteAdd(&netlink.Route{
				Gw:  gw,
				Dst: expected[re],
			}); err != nil {
				return errors.Wrapf(err, "netlink.RouteAdd %q", expected[re].String())
			}
		}
	}

	return nil
}

func routeFields(route netlink.Route) (fields []zapcore.Field) {
	if route.Gw != nil {
		fields = append(fields, zap.String("gw", route.Gw.String()))
	}
	if route.Dst != nil {
		fields = append(fields, zap.String("dst", route.Dst.String()))
	}
	if route.Src != nil {
		fields = append(fields, zap.String("src", route.Src.String()))
	}
	return
}

func enforceDefault(link netlink.Link, gw net.IP, log *zap.Logger) error {
	routes, err := netlink.RouteList(link, netlink.FAMILY_V6)
	if err != nil {
		return errors.Wrap(err, "netlink.RouteList")
	}

	var found *netlink.Route
	for index := range routes {
		fields := routeFields(routes[index])
		log.Debug("Got route", fields...)
		if routes[index].Gw == nil {
			log.Debug("Skip link route", fields...)
			continue
		} else if routes[index].Dst == nil {
			if found != nil {
				return errors.Errorf("more than 1 default gateway")
			}
			log.Debug("Found default", fields...)
			found = &routes[index]
		}
		log.Debug("Skip non default routes", fields...)
	}

	if found == nil {
		if gw == nil {
			log.Debug("No default gw found, good")
			return nil
		}
		log.Debug("No default gw found, add one")
		return errors.Wrap(netlink.RouteAdd(&netlink.Route{Gw: gw}), "RouteAdd")
	} else if gw == nil {
		log.Debug("Default route exist, remove")
		return errors.Wrap(netlink.RouteDel(found), "netlink.RouteDel")
	}

	if found.Gw.Equal(gw) {
		log.Debug("Default gateway already correctly configured", zap.String("gw", gw.String()))
		return nil
	}

	l := log.With(zap.String("existing", found.Gw.String()), zap.String("asked", gw.String()))
	l.Debug("Invalid default route, remove")
	if err = netlink.RouteDel(found); err != nil {
		return errors.Wrap(err, "netlink.RouteDel")
	}
	l.Debug("Removed, add new gateway")
	return errors.Wrap(netlink.RouteAdd(&netlink.Route{Gw: gw}), "RouteAdd")
}

// getOrCreateTun make sure an interface exists
func getOrCreateTun(ifaceName string, log *zap.Logger) (netlink.Link, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err == nil {
		if link.Type() != "tun" {
			return nil, errors.New("Link exists, but it's not a TUN or a TAP")
		}
		return link, nil
	}

	if err.Error() != "Link not found" {
		return nil, errors.Wrap(err, "netlink.LinkByName")
	}

	log.Debug("Link not existing, try to create")
	link = &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name: ifaceName,
		},
		Mode:  netlink.TUNTAP_MODE_TUN,
		Flags: netlink.TUNTAP_DEFAULTS,
	}
	if err = netlink.LinkAdd(link); err != nil {
		return nil, errors.Wrap(err, "netlink.LinkAdd")
	}
	log.Debug("Created")
	return link, nil
}

func main() {
	ifaceName := flag.String("tun", "tun0", "Tun interface")
	localAddressStr := flag.String("local", "", "Interface IPv6 address")
	remoteAddressStr := flag.String("remote", "", "Interface IPv6 address")
	mtu := flag.Uint("mtu", 1500, "MTU")
	setDefaultGw := flag.Bool("default", false, "Set default gw other side of the tunnel")
	routesStr := flag.String("routes", "", "Additional networks to route")

	flag.Parse()

	log, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	if len(*ifaceName) == 0 {
		log.Fatal("Missing -tun")
	}

	if len(*localAddressStr) == 0 {
		log.Fatal("Missing -local")
	}

	if len(*remoteAddressStr) == 0 {
		log.Fatal("Missing -remote")
	}

	log = log.With(zap.String("iface", *ifaceName), zap.Uint("mtu", *mtu))

	localIP, localNet, err := net.ParseCIDR(*localAddressStr)
	if err != nil {
		log.Fatal("Can't parse -local", zap.Error(err))
	}
	localAddress := &net.IPNet{
		IP:   localIP,
		Mask: localNet.Mask,
	}

	remoteIP, remoteNet, err := net.ParseCIDR(*remoteAddressStr)
	if err != nil {
		log.Fatal("Can't parse -remote", zap.Error(err))
	}

	if remoteIP.Equal(localIP) {
		log.Fatal("-local and -remote are the same")
	}

	if !remoteNet.Contains(localIP) {
		log.Fatal("-remote network don't hold -local", zap.String("remote_net", remoteNet.String()), zap.String("local", localIP.String()))
	}

	var destinations []*net.IPNet
	if len(*routesStr) > 0 {
		for index, routeStr := range strings.Split(*routesStr, ",") {
			_, ipnet, err := net.ParseCIDR(routeStr)
			if err != nil {
				log.Fatal("Can't parse route", zap.String("route", routeStr), zap.Int("index", index))
			}
			destinations = append(destinations, ipnet)
		}
	}

	tunLink, err := getOrCreateTun(*ifaceName, log)
	if err != nil {
		log.Fatal("Can't get or create tun", zap.Error(err))
	}

	if err = netlink.LinkSetMTU(tunLink, int(*mtu)); err != nil {
		log.Fatal("Can't set MTU", zap.Error(err))
	}

	if err = enforceIPNet(tunLink, []*net.IPNet{localAddress}, netlink.FAMILY_V6, log); err != nil {
		log.Fatal("Can't enforce ipnet", zap.Error(err))
	}

	if err = netlink.LinkSetUp(tunLink); err != nil {
		log.Fatal("Can't set interface UP", zap.Error(err))
	}

	var gw net.IP
	if *setDefaultGw {
		gw = remoteIP
	} else {
		gw = nil
	}

	if err = enforceDefault(tunLink, gw, log); err != nil {
		log.Fatal("Can't enforce default gateway", zap.Error(err))
	}

	if err = enforceRoutes(tunLink, destinations, remoteIP, netlink.FAMILY_V6, log); err != nil {
		log.Fatal("Can't enforce routes", zap.Error(err))
	}
}
