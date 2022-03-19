package qkms_dal

import (
	"context"
	"errors"
	"fmt"

	qkms_model "qkms/model"

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
		glog.Errorf("Connect database failed. err=%v config=%v", err, cfg)
		return err
	}
	d.DB = db
	//自动迁移，如果表已经存在不会重新创建。
	d.DB.AutoMigrate(&qkms_model.AccessKey{}, &qkms_model.KeyAuthorization{}, &qkms_model.KeyAuthorization{})
	return err
}

func (d *BaseDal) Query(ctx context.Context) *gorm.DB {
	return d.DB.WithContext(ctx)
}

var (
	dalCli *Dal
)

type Dal struct {
	cli BaseDal
}

func (d *Dal) Query(ctx context.Context) *gorm.DB {
	return d.cli.WithContext(ctx)
}

func (d *Dal) IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, gorm.ErrRecordNotFound)
}

func MustInit(cfg DBConfig) {
	dalCli = &Dal{}
	dalCli.cli.MustInit(cfg)
}

func GetDal() *Dal {
	if dalCli == nil {
		glog.Fatalf("dal not initialized")
		return nil
	}
	return dalCli
}