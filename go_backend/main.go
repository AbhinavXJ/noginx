package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type Feature struct {
	Duration               float64 `json:"duration"`
	ProtocolType           float64 `json:"protocol_type"`
	Service                float64 `json:"service"`
	Flag                   float64 `json:"flag"`
	SrcBytes               float64 `json:"src_bytes"`
	DstBytes               float64 `json:"dst_bytes"`
	Land                   float64 `json:"land"`
	WrongFragment          float64 `json:"wrong_fragment"`
	Urgent                 float64 `json:"urgent"`
	Hot                    float64 `json:"hot"`
	NumFailedLogins        float64 `json:"num_failed_logins"`
	LoggedIn               float64 `json:"logged_in"`
	NumCompromised         float64 `json:"num_compromised"`
	RootShell              float64 `json:"root_shell"`
	SuAttempted            float64 `json:"su_attempted"`
	NumRoot                float64 `json:"num_root"`
	NumFileCreations       float64 `json:"num_file_creations"`
	NumShells              float64 `json:"num_shells"`
	NumAccessFiles         float64 `json:"num_access_files"`
	NumOutboundCmds        float64 `json:"num_outbound_cmds"`
	IsHostLogin            float64 `json:"is_host_login"`
	IsGuestLogin           float64 `json:"is_guest_login"`
	Count                  float64 `json:"count"`
	SrvCount               float64 `json:"srv_count"`
	SerrorRate             float64 `json:"serror_rate"`
	SrvSerrorRate          float64 `json:"srv_serror_rate"`
	RerrorRate             float64 `json:"rerror_rate"`
	SrvRerrorRate          float64 `json:"srv_rerror_rate"`
	SameSrvRate            float64 `json:"same_srv_rate"`
	DiffSrvRate            float64 `json:"diff_srv_rate"`
	SrvDiffHostRate        float64 `json:"srv_diff_host_rate"`
	DstHostCount           float64 `json:"dst_host_count"`
	DstHostSrvCount        float64 `json:"dst_host_srv_count"`
	DstHostSameSrvRate     float64 `json:"dst_host_same_srv_rate"`
	DstHostDiffSrvRate     float64 `json:"dst_host_diff_srv_rate"`
	DstHostSameSrcPortRate float64 `json:"dst_host_same_src_port_rate"`
	DstHostSrvDiffHostRate float64 `json:"dst_host_srv_diff_host_rate"`
	DstHostSerrorRate      float64 `json:"dst_host_serror_rate"`
	DstHostSrvSerrorRate   float64 `json:"dst_host_srv_serror_rate"`
	DstHostRerrorRate      float64 `json:"dst_host_rerror_rate"`
	DstHostSrvRerrorRate   float64 `json:"dst_host_srv_rerror_rate"`
}

var protocolTypeMap = map[string]int{
	"icmp": 0,
	"tcp":  1,
	"udp":  2,
}

var serviceMap = map[string]int{
	"IRC": 0, "X11": 1, "Z39_50": 2, "auth": 3, "bgp": 4, "courier": 5,
	"csnet_ns": 6, "ctf": 7, "daytime": 8, "discard": 9, "domain": 10,
	"domain_u": 11, "echo": 12, "eco_i": 13, "ecr_i": 14, "efs": 15,
	"exec": 16, "finger": 17, "ftp": 18, "ftp_data": 19, "gopher": 20,
	"hostnames": 21, "http": 22, "http_443": 23, "imap4": 24,
	"iso_tsap": 25, "klogin": 26, "kshell": 27, "ldap": 28, "link": 29,
	"login": 30, "mtp": 31, "name": 32, "netbios_dgm": 33, "netbios_ns": 34,
	"netbios_ssn": 35, "netstat": 36, "nnsp": 37, "nntp": 38, "ntp_u": 39,
	"other": 40, "pm_dump": 41, "pop_2": 42, "pop_3": 43, "printer": 44,
	"private": 45, "red_i": 46, "remote_job": 47, "rje": 48, "shell": 49,
	"smtp": 50, "sql_net": 51, "ssh": 52, "sunrpc": 53, "supdup": 54,
	"systat": 55, "telnet": 56, "tftp_u": 57, "tim_i": 58, "time": 59,
	"urh_i": 60, "urp_i": 61, "uucp": 62, "uucp_path": 63, "vmnet": 64,
	"whois": 65,
}

var flagMap = map[string]int{
	"OTH":    0,
	"REJ":    1,
	"RSTO":   2,
	"RSTOS0": 3,
	"RSTR":   4,
	"S0":     5,
	"S1":     6,
	"S2":     7,
	"S3":     8,
	"SF":     9,
	"SH":     10,
}

type Payload struct {
	Features []Feature `json:"features"`
}

type Prediction struct {
	Anamoly bool `json:"anomaly"`
}

// var prediction []Prediction

func main() {
	file, err := os.Open("network_logs.csv")
	if err != nil {
		log.Fatal("unable to open csv file")
		return
	}

	defer file.Close()

	reader := csv.NewReader(file)

	var req Payload

	for {
		record, err := reader.Read()
		fmt.Println(record)
		if err == io.EOF {
			fmt.Println("end of file reached,all records parsed")
			fmt.Println(req)
			break

		}

		if len(record) < 41 {
			fmt.Println("Skipping malformed record:", record)
			continue
		}

		for index, val := range record {

			record[index] = strings.TrimPrefix(val, "b'")
			record[index] = strings.TrimSuffix(record[index], "'")

		}

		f := Feature{
			Duration:               parseFloat(record[0]),
			ProtocolType:           float64(protocolTypeMap[record[1]]),
			Service:                float64(serviceMap[record[2]]),
			Flag:                   float64(flagMap[record[3]]),
			SrcBytes:               parseFloat(record[4]),
			DstBytes:               parseFloat(record[5]),
			Land:                   parseFloat(record[6]),
			WrongFragment:          parseFloat(record[7]),
			Urgent:                 parseFloat(record[8]),
			Hot:                    parseFloat(record[9]),
			NumFailedLogins:        parseFloat(record[10]),
			LoggedIn:               parseFloat(record[11]),
			NumCompromised:         parseFloat(record[12]),
			RootShell:              parseFloat(record[13]),
			SuAttempted:            parseFloat(record[14]),
			NumRoot:                parseFloat(record[15]),
			NumFileCreations:       parseFloat(record[16]),
			NumShells:              parseFloat(record[17]),
			NumAccessFiles:         parseFloat(record[18]),
			NumOutboundCmds:        parseFloat(record[19]),
			IsHostLogin:            parseFloat(record[20]),
			IsGuestLogin:           parseFloat(record[21]),
			Count:                  parseFloat(record[22]),
			SrvCount:               parseFloat(record[23]),
			SerrorRate:             parseFloat(record[24]),
			SrvSerrorRate:          parseFloat(record[25]),
			RerrorRate:             parseFloat(record[26]),
			SrvRerrorRate:          parseFloat(record[27]),
			SameSrvRate:            parseFloat(record[28]),
			DiffSrvRate:            parseFloat(record[29]),
			SrvDiffHostRate:        parseFloat(record[30]),
			DstHostCount:           parseFloat(record[31]),
			DstHostSrvCount:        parseFloat(record[32]),
			DstHostSameSrvRate:     parseFloat(record[33]),
			DstHostDiffSrvRate:     parseFloat(record[34]),
			DstHostSameSrcPortRate: parseFloat(record[35]),
			DstHostSrvDiffHostRate: parseFloat(record[36]),
			DstHostSerrorRate:      parseFloat(record[37]),
			DstHostSrvSerrorRate:   parseFloat(record[38]),
			DstHostRerrorRate:      parseFloat(record[39]),
			DstHostSrvRerrorRate:   parseFloat(record[40]),
		}
		req.Features = append(req.Features, f)
		// fmt.Println(record)
		// time.Sleep(time.Second)
	}

	prediction, err := sendPOSTRequest("http://localhost:8000/predict", req)

	if err != nil {
		log.Fatal("Error sending post request", err)
	}
	fmt.Println(prediction)

}

func sendPOSTRequest(url string, payload Payload) ([]Prediction, error) {
	var prediction []Prediction
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("cant convert to json", err)
		return nil, err
	}
	res, err := http.Post(url, "application/json", strings.NewReader(string(jsonData)))

	if err != nil {
		fmt.Println("error sending post request: ", err)
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		fmt.Println("Request failed with status code:", res.StatusCode)
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return nil, err
	}
	err = json.Unmarshal(body, &prediction)

	if err != nil {
		fmt.Println("Unable to decode the response")
		return nil, err
	}

	return prediction, nil
}

//	func parseFloat(s string) int {
//		n, _ := strconv.Atoi(s)
//		return n
//	}
func parseFloat(s string) float64 {
	n, _ := strconv.ParseFloat(s, 64)
	return n
}
