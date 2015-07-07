package main

import (
	"github.com/xjbt/ts"
	"os"
	"path/filepath"
	"strconv"
	"fmt"
	"encoding/json"
)

type Logger struct {
	Pid int
	Root string
	AdaptFieldPrivDataLog *os.File
}

type AdaptOut struct {
	Pos int64
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

	// PCR PID -> PCR values
	var progPcrList = make(map[int][]ts.PcrInfo)

	pkts = ts.ParseFile(fname)
	psiParser := ts.NewPsiParser()
	for pkt := range pkts {
		if ok := psiParser.Parse(pkt); ok {
			psiParser.Report(outdir)
			break
		}
	}

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
		records[pid] = ts.CreateRecord(pid, ts.GetStreamType(s))
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
