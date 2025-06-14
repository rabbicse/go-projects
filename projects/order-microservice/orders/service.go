package main

import (
	"context"
	"log"

	"github.com/rabbicse/go-projects/order-microservice/common"
	pb "github.com/rabbicse/go-projects/order-microservice/common/api"
)

type service struct {
	store OrdersService
}

func NewService(store OrdersStore) *service {
	return &service{}
}

func (s *service) CreateOrder(context.Context) error {
	return nil
}

func (s *service) ValidateOrder(ctx context.Context, p *pb.CreateOrderRequest) error {
	if len(p.Items) == 0 {
		return common.ErrNoItems
	}

	mergedItems := mergeItemsQuantities(p.Items)
	log.Print(mergedItems)

	return nil
}

func mergeItemsQuantities(items []*pb.ItemsWithQuantity) []*pb.ItemsWithQuantity {
	merged := make([]*pb.ItemsWithQuantity, 0)

	for _, item := range items {
		found := false
		for _, finalItem := range merged {
			if finalItem.ID == item.ID {
				finalItem.Quantity += item.Quantity
				found = true
				break
			}
		}

		if !found {
			merged = append(merged, item)
		}
	}

	return merged
}
