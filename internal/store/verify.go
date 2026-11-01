package store

import (
	"fmt"

	"github.com/DeathHapyness/loger/internal/event"
)

type VerifyReport struct {
	Records      uint64
	Problems     []string
	FirstSeq     uint64
	HasFirst     bool
	RotatedFiles int
}

// Verify confere o hash de cada registro, o encadeamento e a sequência.
func Verify(dir string) (*VerifyReport, error) {
	files := LogFiles(dir)
	if len(files) == 0 {
		return nil, NoLogs(dir)
	}
	rep := &VerifyReport{RotatedFiles: len(files) - 1}
	var prevSeq uint64
	var prevHash string
	havePrev := false
	for _, path := range files {
		err := EachLine(path, func(n int, line []byte) bool {
			loc := fmt.Sprintf("%s:%d", path, n)
			r, err := event.Parse(line)
			if err != nil {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%s: linha ilegível (%v)", loc, err))
				return true
			}
			rep.Records++
			if !rep.HasFirst {
				rep.FirstSeq, rep.HasFirst = r.Seq, true
			}
			if r.Kind == "loger.log_tampered" || r.Kind == "loger.unclean_stop" {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%s: o próprio Loger registrou: %s", loc, r.Msg))
			}
			if r.ComputeHash() != r.Hash {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%s: seq %d foi ALTERADO (hash não confere)", loc, r.Seq))
			}
			if havePrev {
				if r.Prev != prevHash {
					rep.Problems = append(rep.Problems, fmt.Sprintf(
						"%s: corrente quebrada entre seq %d e seq %d (registros removidos ou inseridos)", loc, prevSeq, r.Seq))
				} else if r.Seq != prevSeq+1 {
					rep.Problems = append(rep.Problems, fmt.Sprintf("%s: sequência pulou de %d para %d", loc, prevSeq, r.Seq))
				}
			}
			prevSeq, prevHash, havePrev = r.Seq, r.Hash, true
			return true
		})
		if err != nil {
			return nil, err
		}
	}
	return rep, nil
}
