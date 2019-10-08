// main.go
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"runtime"
	"reflect"
	"syscall"
)

type load_balancer struct {
	address             string
	ifname              string
	contention_ratio    int
	current_connections int
}

// The load balancer used in the previous connection
var lb_index int = 0

// List of all load balancers
var lb_list []load_balancer

// Mutex to serialize access to function get_load_balancer
var mutex *sync.Mutex

/*
	Get a load balancer according to contention ratio
*/
func get_load_balancer() *load_balancer {
	mutex.Lock()
	lb := &lb_list[lb_index]
	lb.current_connections += 1

	if lb.current_connections == lb.contention_ratio {
		lb.current_connections = 0
		lb_index += 1

		if lb_index == len(lb_list) {
			lb_index = 0
		}
	}
	mutex.Unlock()
	return lb
}

/*
	Joins the local and remote connections together.
*/
func forward_connections(local_conn, remote_conn net.Conn) {
	go func() {
		defer remote_conn.Close()
		defer local_conn.Close()
		_, err := io.Copy(remote_conn, local_conn)
		if err != nil {
			return
		}
	}()

	go func() {
		defer remote_conn.Close()
		defer local_conn.Close()
		_, err := io.Copy(local_conn, remote_conn)
		if err != nil {
			return
		}
	}()
}

/*
	bind conn to interface
*/
func bindToDevice(conn net.Conn, device string) (net.Conn, error) {
	ptrVal := reflect.ValueOf(conn)
	tc := ptrVal.Interface().(*net.TCPConn)
	f, _ := tc.File()
	defer f.Close()

	err := syscall.BindToDevice(int(f.Fd()), device)
	if err != nil {
		return nil, err
	}

	// https://github.com/ryanchapman/go-any-proxy/blob/master/any_proxy.go#L459
	newConn, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	return newConn, nil
}

/*

 */
func server_response(local_conn net.Conn, address string) {
	load_balancer := get_load_balancer()
	load_balancer_addr := load_balancer.address

	local_addr, _ := net.ResolveTCPAddr("tcp4", load_balancer_addr)
	remote_addr, _ := net.ResolveTCPAddr("tcp4", address)
	var remote_conn net.Conn
	var err error
	if load_balancer_addr != "" {
		remote_conn, err = net.DialTCP("tcp4", local_addr, remote_addr)
	} else {
		remote_conn, err = net.Dial("tcp4", address)
		if err == nil {
			remote_conn, err = bindToDevice(remote_conn, load_balancer.ifname)
			if err != nil {
				log.Fatal("[FATAL] Failed to bind socket to interface: ", err)
			}
		}
	}

	if err != nil {
		log.Println("[WARN]", address, "->", load_balancer_addr, fmt.Sprintf("{%s}", err))
		local_conn.Write([]byte{5, NETWORK_UNREACHABLE, 0, 1, 0, 0, 0, 0, 0, 0})
		local_conn.Close()
		return
	}
	log.Println("[DEBUG]", address, "->", load_balancer_addr, load_balancer.ifname)
	local_conn.Write([]byte{5, SUCCESS, 0, 1, 0, 0, 0, 0, 0, 0})
	forward_connections(local_conn, remote_conn)
}

/*

 */
func handle_connection(conn net.Conn) {
	if address, err := Handle_socks_connection(conn); err == nil {
		server_response(conn, address)
	}
}

/*
	Detect the addresses which can  be used for dispatching.
	Alternate to ipconfig/ifconfig
*/
func detect_interfaces() {
	fmt.Println("--- Listing the available adresses for dispatching")
	ifaces, _ := net.Interfaces()

	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp == net.FlagUp) && (iface.Flags&net.FlagLoopback != net.FlagLoopback) {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						fmt.Printf("[+] %s, IPv4:%s\n", iface.Name, ipnet.IP.String())
					}
				}
			}
		}
	}

}

/*
	Parses the command line arguements to obtain the list of load balancers
*/
func parse_load_balancers(args []string) {
	if len(args) == 0 {
		log.Fatal("[FATAL] Please specify one or more load balancers")
	}

	lb_list = make([]load_balancer, flag.NArg())

	for idx, a := range args {
		splitted := strings.Split(a, "@")
		var lb_ip = splitted[0]
		var lb_ifname string
		if net.ParseIP(lb_ip).To4() == nil {
			// use it as ifname in Linux
			if runtime.GOOS == "linux" {
				lb_ifname = lb_ip
				lb_ip = ""
				if _, err := net.InterfaceByName(lb_ifname);err!=nil {
					log.Fatal("[FATAL] Invalid interface name ", lb_ifname)
				}
			} else {
				log.Fatal("[FATAL] Invalid address ", lb_ip)
			}
		} else {
			lb_ip = fmt.Sprintf("%s:0", lb_ip)
		}
		var cont_ratio int = 1
		if len(splitted) > 1 {
			var err error
			cont_ratio, err = strconv.Atoi(splitted[1])
			if err != nil || cont_ratio <= 0 {
				log.Fatal("[FATAL] Invalid contention ratio for ", lb_ip)
			}
		}

		log.Printf("[INFO] Load balancer %d: %s%s, contention ratio: %d\n", idx+1, lb_ip, lb_ifname, cont_ratio)
		lb_list[idx] = load_balancer{address: lb_ip, contention_ratio: cont_ratio, current_connections: 0, ifname: lb_ifname}
	}
}

/*
	Main function
*/
func main() {
	var lhost = flag.String("lhost", "127.0.0.1", "the host to listen for SOCKS connection")
	var lport = flag.Int("lport", 1080, "the local port to listen for SOCKS connection")
	var detect = flag.Bool("list", false, "shows the available addresses for dispatching ")

	flag.Parse()
	if *detect {
		detect_interfaces()
		return
	}

	// Disable timestamp in log messages
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	// Check for valid IP
	if net.ParseIP(*lhost).To4() == nil {
		log.Fatal("[FATAL] Invalid host ", *lhost)
	}

	// Check for valid port
	if *lport < 1 || *lport > 65535 {
		log.Fatal("[FATAL] Invalid port ", *lport)
	}

	//Parse remaining string to get addresses of load balancers
	parse_load_balancers(flag.Args())

	local_bind_address := fmt.Sprintf("%s:%d", *lhost, *lport)

	// Start SOCKS server
	l, err := net.Listen("tcp4", local_bind_address)
	if err != nil {
		log.Fatalln("[FATAL] Could not start SOCKS server at", local_bind_address)
	}
	log.Println("[INFO] SOCKS server started at", local_bind_address)
	defer l.Close()

	mutex = &sync.Mutex{}
	for {
		conn, _ := l.Accept()
		go handle_connection(conn)
	}
}
