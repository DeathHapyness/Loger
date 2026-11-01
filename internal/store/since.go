package store

import (
	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/util"
)

// FilesSince tira do começo da lista os arquivos rotacionados cujo último registro é
// anterior a since: nenhum deles pode ter registros do período.
func FilesSince(files []string, since int64) []string {
	for len(files) > 1 {
		line, ok := util.LastLine(files[0])
		if !ok {
			break
		}
		r, err := event.Parse(line)
		if err != nil || r.TsMs() >= since {
			break
		}
		files = files[1:]
	}
	return files
}
