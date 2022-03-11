package qkms_dal

import (
	"context"
	"fmt"

	"github.com/golang/glog"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DBConfig struct {
	Username string
	Password string
	DbName   string
	Host     string
	Port     int32
}

type BaseDal struct {
	*gorm.DB
}

func (d *BaseDal) MustInit(cfg DBConfig) {
	if err := d.Init(cfg); err != nil {
		panic(err)
	}
}

func (d *BaseDal) Init(cfg DBConfig) error {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username, cfg.Password, cfg.Host, cfg.Port, cfg.DbName,
	)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error), // log sql
	})
	if err != nil {
		glog.Errorf("connect database failed. err=%v config=%v", err, cfg)
		return err
	}
	d.DB = db
	return err
}

func (d *BaseDal) Query(ctx context.Context) *gorm.DB {
	return d.DB.WithContext(ctx)
}
