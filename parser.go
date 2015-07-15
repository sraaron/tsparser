package main

import (
	"encoding/json"
	"fmt"
	"github.com/xjbt/ts"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var Root string

type Logger struct {
	Pid                   int
	Root                  string
	AdaptFieldPrivDataLog *os.File
}

type AdaptOut struct {
	Pos     int64
	Content ts.AdaptFieldPrivData
}

func newLogger(pid int, root string) *Logger {
	logger := Logger{}
	logger.Pid = pid
	logger.Root = root
	return &logger
}

func (logger *Logger) LogAdaptFieldPrivData(pkt *ts.TsPkt) {
	if pkt.AdaptField == nil || pkt.AdaptField.PrivateData == nil {
		return
	}
	data := pkt.AdaptField.PrivateData
	if logger.AdaptFieldPrivDataLog == nil {
		fname := filepath.Join(logger.Root, strconv.Itoa(logger.Pid)+"-tspriv.csv")
		var err error
		logger.AdaptFieldPrivDataLog, err = os.Create(fname)
		if err != nil {
			panic(err)
		}
	}
	privList := ts.ParseAdaptFieldPrivData(data)
	for _, p := range privList {
		adaptOut := AdaptOut{pkt.Pos, p}
		c, _ := json.Marshal(adaptOut)
		fmt.Fprintln(logger.AdaptFieldPrivDataLog, string(c))
	}
}

func parse(fname string, outdir string, psiOnly bool) {
	var pkts chan *ts.TsPkt

	Root = outdir

	// PCR PID -> PCR values
	var progPcrList = make(map[int][]ts.PcrInfo)

	pkts = ts.ParseFile(fname)
	psiParser := ts.NewPsiParser()
	for pkt := range pkts {
		if ok := psiParser.Parse(pkt); ok {
			break
		}
	}
	psiParser.Finish()
	psiParser.Report(outdir)

	if psiOnly {
		return
	}

	streams := psiParser.GetStreams()

	pcrs := psiParser.GetPcrs()
	for pcrPid, _ := range pcrs {
		// Default PCR list length: 1500 = 25Hz * 60s
		progPcrList[pcrPid] = make([]ts.PcrInfo, 0)
	}

	records := make(map[int]ts.Record)
	loggers := make(map[int]*Logger)
	for pid, s := range streams {
		records[pid] = ts.CreateRecord(pid, ts.GetStreamType(s), outdir)
		loggers[pid] = newLogger(pid, outdir)
	}

	pkts = ts.ParseFile(fname)
	for pkt := range pkts {
		logger := loggers[pkt.Pid]
		if logger != nil {
			logger.LogAdaptFieldPrivData(pkt)
		}

		if pcr, ok := pkt.PCR(); ok {
			if pids, ok := pcrs[pkt.Pid]; ok {
				// Save the PCR value
				progPcrList[pkt.Pid] = append(
					progPcrList[pkt.Pid],
					ts.PcrInfo{pkt.Pos, pcr})
				for _, pid := range pids {
					records[pid].NotifyTime(pcr, pkt.Pos)
				}
			}
		}

		if record, ok := records[pkt.Pid]; ok {
			record.Process(pkt)
		}
	}

	for pcrPid, pcrList := range progPcrList {
		ts.CheckPcrInterval(outdir, pcrPid, pcrList)
	}

	for _, record := range records {
		record.Flush()
		record.Report(outdir)
	}

	verify(psiParser.Info)
}

func extract(fname string, outdir string, pid int) {
	var pkts chan *ts.TsPkt
	pkts = ts.ParseFile(fname)

	of := filepath.Join(outdir, strconv.Itoa(pid)+".es")
	f, err := os.Create(of)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	for pkt := range pkts {
		if pkt.Pid == pid {
			f.Write(pkt.Data)
		}
	}
}

func verify(psiInfo ts.Info) {
	result := map[string]interface{}{}
	for _, prog := range psiInfo.Programs {
		result["keyframe-alignment"] = verifyKeyframeAlignment(prog)
	}
	logJson("verified", result)
}

func verifyKeyframeAlignment(prog ts.Program) map[string]interface{} {
	sctePids, videoPid := []string{}, ""
	for pid, strm := range prog.Streams {
		switch strm.StreamType {
		case "SCTE-35":
			sctePids = append(sctePids, pid)
		case "MPEG-2 Video", "MPEG-4 Video", "MPEG-4 AVC Video":
			videoPid = pid
		}
	}

	result := map[string]interface{}{}
	for _, sctePid := range sctePids {
		pair := sctePid + ":" + videoPid
		result[pair] = verifySpliceWithKeyframe(sctePid, videoPid)
	}
	return result
}

func verifySpliceWithKeyframe(sctePid, videoPid string) map[string]bool {
	splice := map[string]bool{}
	iframe := map[string]bool{}

	parseCsv(sctePid, func(fields []string) {
		if len(fields) > 3 {
			pts, _ := strconv.ParseInt(fields[3], 10, 64)
			adj, _ := strconv.ParseInt(fields[4], 10, 64)
			key := strconv.FormatInt(pts+adj, 10)
			splice[key] = false
		}
	})

	parseCsv(videoPid+"-iframe", func(fields []string) {
		if len(fields) > 1 {
			iframe[fields[1]] = false
		}
	})

	for pts, _ := range splice {
		if _, ok := iframe[pts]; ok {
			splice[pts] = true
		}
	}

	return splice
}

func parseCsv(filename string, handle func([]string)) {
	content, err := ioutil.ReadFile(filepath.Join(Root, filename+".csv"))
	check(err)

	lines := strings.Split(string(content), "\n")
	lines = lines[1:]
	for _, line := range lines {
		fields := strings.Split(line, ", ")
		handle(fields)
	}
}

func logJson(filename string, v interface{}) {
	w, err := os.Create(filepath.Join(Root, filename+".json"))
	check(err)
	defer w.Close()

	b, err := json.MarshalIndent(v, "", "  ")
	check(err)
	fmt.Fprintln(w, string(b))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
