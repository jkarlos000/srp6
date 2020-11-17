package srp

import (
	"testing"
)

func TestProofVerifier(t *testing.T) {
	username := "Jkarlos"
	password := "Cambiamejk1!."
	auth := New()
	auth.SetSalt("AF16F36FE509CB4C8BD4191D2DB93C05196AE49AC843C4E393A7CC63266D83DC")
	identifier := Hash(username, password)
	auth.ComputeVerifier(identifier)

	if !auth.ProofVerifier("761C5B181E3C33517C6102B369370D9382823FC3D1DF48682DAA0F425DB6FDC2") {
		t.Fatal("Contraseña no válida")
	}

}


//s: AF16F36FE509CB4C8BD4191D2DB93C05196AE49AC843C4E393A7CC63266D83DC
//v: 761C5B181E3C33517C6102B369370D9382823FC3D1DF48682DAA0F425DB6FDC2