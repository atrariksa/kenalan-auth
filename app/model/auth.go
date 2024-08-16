package model

import "time"

type Auth struct {
	ID        int64     `gorm:"column:id" json:"id"`
	Fullname  string    `gorm:"column:full_name" json:"full_name"`
	Gender    string    `gorm:"column:gender" json:"gender"`
	DOB       time.Time `gorm:"column:dob" json:"dob"`
	Email     string    `gorm:"column:email" json:"email"`
	Password  string    `gorm:"column:password" json:"password"`
	PhotoURL  string    `gorm:"column:photo_url" json:"photo_url"`
	CreatedAt time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at" json:"updated_at"`
}

func (Auth) TableName() string {
	return "auths"
}
