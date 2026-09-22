package domain

type Subnet struct {
	CIDR   string
	IsIPv6 bool
}

type NetworkList struct {
	IPv4Subnets []string
	IPv6Subnets []string
}

func NewNetworkList() *NetworkList {
	return &NetworkList{
		IPv4Subnets: make([]string, 0),
		IPv6Subnets: make([]string, 0),
	}
}

func (nl *NetworkList) Add(subnet string, isIPv6 bool) {
	if isIPv6 {
		nl.IPv6Subnets = append(nl.IPv6Subnets, subnet)
	} else {
		nl.IPv4Subnets = append(nl.IPv4Subnets, subnet)
	}
}

func (nl *NetworkList) IPv4Count() int {
	return len(nl.IPv4Subnets)
}

func (nl *NetworkList) IPv6Count() int {
	return len(nl.IPv6Subnets)
}

func (nl *NetworkList) TotalCount() int {
	return nl.IPv4Count() + nl.IPv6Count()
}
