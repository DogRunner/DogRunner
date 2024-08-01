package repository

import (
	"github.com/wanrun-develop/wanrun/internal/dog/core/model"
	"gorm.io/gorm"
)

type IDogRepository interface {
	GetAllDogs(dogs *[]model.Dog) error
	GetDogByID(dog *model.Dog, dogID uint) error
}

type dogRepository struct {
	db *gorm.DB
}

func NewDogRepository(db *gorm.DB) IDogRepository {
	return &dogRepository{db}
}

func (dr *dogRepository) GetAllDogs(dogs *[]model.Dog) error {
	if err := dr.db.Find(&dogs).Error; err != nil {
		return err
	}
	return nil
}

func (dr *dogRepository) GetDogByID(dog *model.Dog, dogID uint) error {
	if err := dr.db.Where("dog_id = ?", dogID).First(&dog).Error; err != nil {
		return err
	}
	return nil
}
