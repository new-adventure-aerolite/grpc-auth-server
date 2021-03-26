package app

import (
	"time"

	"github.com/patrickmn/go-cache"
)

var store = cache.New(5*time.Minute, 10*time.Minute)
