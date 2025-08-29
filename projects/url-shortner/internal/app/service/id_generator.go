package service

type IDGenerator interface {
	GenerateSnowflakeID() (string, error)
	GenerateID() (string, error)
}
