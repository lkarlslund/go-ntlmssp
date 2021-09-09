package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type challengeMessageFields struct {
	messageHeader
	TargetName      varField
	NegotiateFlags  negotiateFlags
	ServerChallenge [8]byte
	_               [8]byte
	TargetInfo      varField
}

func (m challengeMessageFields) IsValid() bool {
	return m.messageHeader.IsValid() && m.MessageType == 2
}

type challengeMessage struct {
	challengeMessageFields
	TargetName    string
	TargetInfo    map[avID][]byte
	TargetInfoRaw []byte
}

func GetTargetInfoBytes(TargetInfo map[avID][]byte) ([]byte, error) {

	b := bytes.Buffer{}

	for ID, v := range TargetInfo {
		if ID == avIDMsvAvEOL {
			continue
		}
		if err := binary.Write(&b, binary.LittleEndian, &avPair{ID, uint16(len(v))}); err != nil {
			return nil, err
		}
		b.Write(v)
	}

	// Append required MsvAvEOL pair
	if err := binary.Write(&b, binary.LittleEndian, &avPair{avIDMsvAvEOL, 0}); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func (m *challengeMessage) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	err := binary.Read(r, binary.LittleEndian, &m.challengeMessageFields)
	if err != nil {
		return err
	}
	if !m.challengeMessageFields.IsValid() {
		return fmt.Errorf("Message is not a valid challenge message: %+v", m.challengeMessageFields.messageHeader)
	}

	if m.challengeMessageFields.TargetName.Len > 0 {
		m.TargetName, err = m.challengeMessageFields.TargetName.ReadStringFrom(data, m.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEUNICODE))
		if err != nil {
			return err
		}
	}

	if m.challengeMessageFields.TargetInfo.Len > 0 {
		d, err := m.challengeMessageFields.TargetInfo.ReadFrom(data)
		m.TargetInfoRaw = d
		if err != nil {
			return err
		}
		m.TargetInfo = make(map[avID][]byte)
		r := bytes.NewReader(d)
		for {
			var id avID
			var l uint16
			err = binary.Read(r, binary.LittleEndian, &id)
			if err != nil {
				return err
			}
			if id == avIDMsvAvEOL {
				break
			}

			err = binary.Read(r, binary.LittleEndian, &l)
			if err != nil {
				return err
			}
			value := make([]byte, l)
			n, err := r.Read(value)
			if err != nil {
				return err
			}
			if n != int(l) {
				return fmt.Errorf("Expected to read %d bytes, got only %d", l, n)
			}
			m.TargetInfo[id] = value
		}
	}

	return nil
}
