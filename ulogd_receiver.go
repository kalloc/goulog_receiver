package main

import (
    "fmt"
    "net"
    "encoding/binary"
    "sync"
    "http"
    "crypto/cipher"
    "crypto/aes"
    "github.com/jbarham/pgsql.go"
)
type Server struct {
        conn  *net.UDPConn        // Socket that receives UDP pings from the clients
        lk    sync.Mutex          // Lock for peers field
        peers map[string]*client  // Id-to-client map
        cipher *aes.Cipher

}

type client struct {
        id           string
        lastSeen     int64
        addr         *net.UDPAddr
        dials, rings map[string]int64
}

type Packet struct {
        time  uint32;
        protocol uint8;
        source_ip uint32;
        destination_ip uint32;
        source_port uint16;
        destination_port uint16;
        icmp_code uint16;
        icmp_type uint16;
        len uint32;
}

type NetworkBuffer struct {
    buffer []byte
}


func (p *NetworkBuffer) Uint16(i int) uint16 {
    return uint16(binary.LittleEndian.Uint16(p.buffer[i : i+2]))
}

func (p *NetworkBuffer) Uint32(i int) uint32 {
    return uint32(binary.LittleEndian.Uint32(p.buffer[i : i+4]))
}

func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}


func main() {
    uaddr2, err := net.ResolveUDPAddr(":5555",":5555")
    if err != nil {
        fmt.Printf("%v\n", err)
        return
    }
    conn, err := net.ListenUDP("udp", uaddr2)
    if err != nil {
        fmt.Printf("%v\n", err)
        return
    }

    key := []uint8( "some key")
    Cipher, err := aes.NewCipher(key)
    // Start server
    s := &Server{
        conn: conn,
        cipher: Cipher,
    }
    s.listenLoop()
    
}
type CipheredData struct {
    addr *net.UDPAddr;
    b []byte;
    n int;
    ch <- chan int;
}
func (s *Server) listenLoop() {
        received := make(chan CipheredData)
        key := []uint8( "some key")
        
        Cipher, _ := aes.NewCipher(key)
        dbpool, err := pgsql.NewPool("dbname=vpn user=vpn", 11, pgsql.DEFAULT_IDLE_TIMEOUT)
        if err != nil {
            fmt.Printf("error connect to db %v\n",err)
            return
        }

        go decipher(received, Cipher, dbpool)

        for {
            b := make([]byte, 1410 + 1)
            n, addr, err := s.conn.ReadFromUDP(b)
            if err == nil  {
                received <- CipheredData {addr, b, n, make(chan int)}


            }

        }
}
func inet_ntoa(in uint32) (string) {
    return fmt.Sprintf("%d.%d.%d.%d", in&255, in>>8&255, in>>16&255,in>>24&255)
}

func  decipher(ch chan CipheredData, Cipher *aes.Cipher, dbpool *pgsql.Pool)  {

    for {
        data := <- ch
        plain := make([]byte, data.n)
        decrypter := cipher.NewCBCDecrypter(Cipher, data.b[:16])
        decrypter.CryptBlocks(plain,data.b[16:data.n])
        n:=len(plain)
        if string(plain[:2]) != "OK" {
            fmt.Printf("broken packet from %v\n", data.addr)
        }
        order := plain[2:34]
        count := int(plain[34])
        if (count > ((n-35)/21))  || (count*21 > 1410) {
            fmt.Printf("%v Count to long %d\n", data.addr, count) 
            return
        }
        packets := plain[35:n]
        fmt.Printf("packet(s) - %d from %v (%v)\n" , count, data.addr, order)
        for i := 0; i < count; i++ {
            packet := NetworkBuffer{buffer:packets[i*21:(i+1)*21]}
            pkt:=&Packet{time:packet.Uint32(0),protocol:packet.buffer[4], source_ip:packet.Uint32(5), destination_ip:packet.Uint32(9), len:packet.Uint32(17)}
            if pkt.protocol == 1 {
                pkt.icmp_type = packet.Uint16(13)
                pkt.icmp_code = packet.Uint16(15)
            } else {
                pkt.source_port = packet.Uint16(13)
                pkt.destination_port = packet.Uint16(15)
            }               
            conn, _ := dbpool.Acquire() // Get a connection from the pool.
            query := fmt.Sprintf("insert into statistics (order_id, time, source_ip, destination_ip,"+ 
                " source_port, destination_port, protocol, len, icmp_code, icmp_type) " +  
                " values ((select id from orders where cn like '%s%%'), to_timestamp('%d'), '%s', '%s', '%d', '%d', '%d','%d', '%d', '%d')",
                string(order[:31]), pkt.time, inet_ntoa(pkt.source_ip), inet_ntoa(pkt.destination_ip), pkt.source_port, pkt.destination_port, 
                pkt.protocol, pkt.len, pkt.icmp_code, pkt.icmp_type,)
            conn.Query(query)
            dbpool.Release(conn)
        }
    }
}
