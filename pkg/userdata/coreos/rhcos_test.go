package coreos

import (
	"encoding/json"
	"testing"
)

const kubeconfig = `clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURNakNDQWhxZ0F3SUJBZ0lJYnNZaFFHeGFEQUV3RFFZSktvWklodmNOQVFFTEJRQXdOekVTTUJBR0ExVUUKQ3hNSmIzQmxibk5vYVdaME1TRXdId1lEVlFRREV4aHJkV0psTFdGd2FYTmxjblpsY2kxc1lpMXphV2R1WlhJdwpIaGNOTWpBd01qRTBNRGd5TlRVNVdoY05NekF3TWpFeE1EZ3lOVFU1V2pBM01SSXdFQVlEVlFRTEV3bHZjR1Z1CmMyaHBablF4SVRBZkJnTlZCQU1UR0d0MVltVXRZWEJwYzJWeWRtVnlMV3hpTFhOcFoyNWxjakNDQVNJd0RRWUoKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBT21Cb1NPU04zRE1jRlMvQ2NKVXRsRjlPVmtvUEZxdApKTEo3WVVMVlE3Uzd2QW5qcG1Ld1ozT0RpbHlaNVdHQXhTUEdlQ2VDa1BhcWFmemJNK1JKYWhwS2dFbTBNZkN3CmVWdUFTc0IxVVBxUHFVaWNzaElUSTh2dzlVcmllS1dWbkRucW54MFEzZ3VJbXpLaTVDWWZtdmxoRzJMUEZCWHMKd3hVck53Njl6MVZpSy9Cd0J5QnduWDNtbjBGVE9kaktHcThCT0FybGhYNFZvbDhqaGFxWUQxMDUxMS9FaGtRUwp3VjNVWDdRUzRidks0VGtPVVp1M2VnRnJ3blZPVWxnTzR4TnpJTnp1NnVsbEZBaVM5cWllUTMxU3EwTTh2YTRyCndFaEpVdUJRWThmclVoSUEwT21HWjNJVUROamZpaCtVWGoya09pUmdLbytiUUlSRUdsTElBVkVDQXdFQUFhTkMKTUVBd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRk05UApOZjdPTDJDQkZFSTlxdjEyUHVDV2xURFNNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUURveURNaDBhYzhudkNuCkdEZjBMN003cXFuUk82NjZzTnA5WDk3L2RvbTYvNXBGNTVvV3pPcmw4NWM1L2ZnYVVlREF2WlBpeGZJMFM4dDAKUTYwN3hCNHJNTlNSU3E0S1lOQ2pZdnA5eGR3Zm1lRlVpaTZDNTExSENFVTg1MktneDdjQkhhbGJSTkJaL1VXSwo4VG1lZGx3SWpNMEJ0YVcyNk1uY241c0hwdGU1ZE1PV2NadlJNM1R1d2hGNEtvb1JseThkU0pRV0ZPRkFKdzRXCndWSVVkRjRHUGVrR3h0aGh6aFNFOU1oejB2b0lIbFVMUGlNcmNmRHNJcStWK0ZqUVVmYWJCeEllenRXMWV0ck8KS2Zhb1VVazZmUlFWcHJGL2kvNFp4NnhFdXBuamJxd0ZPbGNoOWdINjhtbnZ3cG1nTGVVVE5FTDRNeVMwMlk1MApkNFhITnYrUAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlEUURDQ0FpaWdBd0lCQWdJSVFDMHRMN3kzbTlvd0RRWUpLb1pJaHZjTkFRRUxCUUF3UGpFU01CQUdBMVVFCkN4TUpiM0JsYm5Ob2FXWjBNU2d3SmdZRFZRUURFeDlyZFdKbExXRndhWE5sY25abGNpMXNiMk5oYkdodmMzUXQKYzJsbmJtVnlNQjRYRFRJd01ESXhOREE0TWpVMU9Gb1hEVE13TURJeE1UQTRNalUxT0Zvd1BqRVNNQkFHQTFVRQpDeE1KYjNCbGJuTm9hV1owTVNnd0pnWURWUVFERXg5cmRXSmxMV0Z3YVhObGNuWmxjaTFzYjJOaGJHaHZjM1F0CmMybG5ibVZ5TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF2NDhHamcwd0ZDNysKbTVQVUJvNXFvSmRxcG9SYWZNVzBXbGVYTjdwc214cGVIL2lWRmlyUlI2R0EwbFZ5MytGOW1ERFhwekMxekZsSwo0eTRFTnh6aFR3eDdkejdTWTByZFA3djNndHJ3YTdBR0tyZEZvNkxIMit4NVYwWUJ0UnJINy9BcFIzVW5UaFhkCm9ySkJRdUtTMTJMcUJ1S0VFZzFGT1Irei9vL2RRV00rVkJrTTRndHNXMDJqZnpVeUd0K0FYNEltQmZYNVZrM2sKa3FRSEVtK293a2Q1d2ZpYU5OQkV3dU01RUFqcUNMb2VKSWdLK2FGZ0R5bWlpTGxWcVZEenNON1JyN2pjY1FoZwowSzZMR0FFUk1nbmxVVWxQLzBnVWF3MzJtem1hbDJCeW5NR3d2S2hmVG1lTGJrYTBQcG15N09UUll0bWwzK1YvCkVubDgzUm42WXdJREFRQUJvMEl3UURBT0JnTlZIUThCQWY4RUJBTUNBcVF3RHdZRFZSMFRBUUgvQkFVd0F3RUIKL3pBZEJnTlZIUTRFRmdRVVZZRFoxeFU1RjNsNlZPSmVVUkJQcklYTitHRXdEUVlKS29aSWh2Y05BUUVMQlFBRApnZ0VCQUVVd0pZODAzY1JNdnNBeWN3U2J3OE5WUnNpelhic0l4YlF3WXVPaW5oVndsM0pNRGs3bWMwcStjNWEvCnBMcWJ4NkJWTmFPREFhRnBpV3VUdjU3eExZeFpsZ1BXZWZjT2M3T09ISGpqRDhEdXpVcUZUalJsVzV5cERHUlcKc1VMVmQzcHEzL2t3Wm9oSzVINjdHYnZoSnpyVThyRk5SZzJtOFRkT1ZvYS9vZWJNYVdzRnUwKzlaS1Z4ZGVWYgpLY1Z2SGMxQWFrQWJpUmFFbHdncVdhSVczM21lVWtyMUtGUTNweXhUdkdQTkxISEsxWEpyT3ZzQWJVeVNCRFJICm01Zys2MjI5ZGY4dzdsYmJhR1JGVzlSdGxLUVhJbEU4WEYzakF5ZzdzMkIzN3UvbWZFK2drVVFGU0FuZFozQkYKMHFISFRWbU0zWkdtVnlTZ1JOR2lHMmZrMjJFPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlEVERDQ0FqU2dBd0lCQWdJSVVVQjJ1QlM5UnpBd0RRWUpLb1pJaHZjTkFRRUxCUUF3UkRFU01CQUdBMVVFCkN4TUpiM0JsYm5Ob2FXWjBNUzR3TEFZRFZRUURFeVZyZFdKbExXRndhWE5sY25abGNpMXpaWEoyYVdObExXNWwKZEhkdmNtc3RjMmxuYm1WeU1CNFhEVEl3TURJeE5EQTRNalUxT1ZvWERUTXdNREl4TVRBNE1qVTFPVm93UkRFUwpNQkFHQTFVRUN4TUpiM0JsYm5Ob2FXWjBNUzR3TEFZRFZRUURFeVZyZFdKbExXRndhWE5sY25abGNpMXpaWEoyCmFXTmxMVzVsZEhkdmNtc3RjMmxuYm1WeU1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0MKQVFFQWtUV3Z5V1Vpc2JPM0dZTmVGRVRhTWF5ekI1eDFGWjA3dTNCSndOalNtdm9SeDZXWlBhMmVySWVHazQzMAp2bHVwZ1h6Y0h6Q0pGMWNick5HZkhmUDZGMmlhcVlWWGVVbUhtMUtHZmZZVGVINHRGY2V6ODZna3ZGZy9JVWJyCnptRGxKbjV1RjkrTWlMRS9iUmFoUkV3NWNXeFdPMEVPZUE1a25TMm16eWhpVHlzcnk1TVdrcVhPS1Q2QW1WSW4KTnlMeENTUFU3cnpQbTlRS1Q3MW9TYnJaTHRlSGgwRUpibVdzaW9NMHZxZ1dCd2hjTGs1WVZJTk1tTUFzeTJXKwpuWWVxeGpNUCs3SVBwZUh1TlhRMGRhMW1GUDl5VHJYWHpnbUZ4bFJDYWxpQi9BTUg1anJOWjN6S3RlZ0o3VTIwCm5KTnByYUszdmc3SnJhRzI2VExJUXZvdTNRSURBUUFCbzBJd1FEQU9CZ05WSFE4QkFmOEVCQU1DQXFRd0R3WUQKVlIwVEFRSC9CQVV3QXdFQi96QWRCZ05WSFE0RUZnUVVpRFlPOEZCN2RJSDVnU2h5VGVUOVljcHMrQ2t3RFFZSgpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFGRTNaRm1BTERMdnF0TmhBcTdmWStjOUhVUmZTVitCYzJqajk5YVM1Q1hXCk41b2V0SWJocVdVMWtQR0hwcGJGdTVCU1BuOFA1VXVSeWFCbDhyWm1IMVZleWIyWmNBNyt3Q2FRcjlhYjVPaDIKdVcwZHdPRkNiT0cxSjV2aWFjVE9UWWxTT1RINUM1cFhoSzZYVit6TkFaVm9YUHpYOW4rRXNFY0puM2FJNkhibQprTlpMTzBFRnd4bWI5bFI0dUdMeTZHWUJTZlRFaUt3RmZNbzk0RTY3anFXdWVMaTFvQnk0MnljOFdTakppRHBoCmhsTmRFOC9HYUhQMVJyVmJsVGlzVFlkMnVnUEdaQlJXbzM5MlVTZS9EVzU4ejljRUI3NHZSaWlDc1dsOW1FR2kKOUFiVW1RUVloM1N1VzZoWnZrZW1RU1E4N2JRUGJ3U2ZEbWpHTkVnbzJETT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJRGtEQ0NBbmlnQXdJQkFnSUJBVEFOQmdrcWhraUc5dzBCQVFzRkFEQlpNVmN3VlFZRFZRUURERTV2Y0dWdQpjMmhwWm5RdGEzVmlaUzFoY0dselpYSjJaWEl0YjNCbGNtRjBiM0pmYkc5allXeG9iM04wTFhKbFkyOTJaWEo1CkxYTmxjblpwYm1jdGMybG5ibVZ5UURFMU9ERTJOekUxTURFd0hoY05NakF3TWpFME1Ea3hNVFF3V2hjTk16QXcKTWpFeE1Ea3hNVFF4V2pCWk1WY3dWUVlEVlFRRERFNXZjR1Z1YzJocFpuUXRhM1ZpWlMxaGNHbHpaWEoyWlhJdApiM0JsY21GMGIzSmZiRzlqWVd4b2IzTjBMWEpsWTI5MlpYSjVMWE5sY25acGJtY3RjMmxuYm1WeVFERTFPREUyCk56RTFNREV3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQzhwNGhPTGx2SVdCMkIKUW1wVlM1enhIQW95VXcwbWZKTzM2bVpGM25zODdtNWhUNlZYREFVK2pXOERCWitkMEZRU0FIVzNrNkx0SkdPQgpUYWIrRC8vaTBPTXltclY4Q1JVSmVkVGx0WEg1bVhXZXRYUDFNZVJDMytmTWF1cmY5K0d6blpMaDQ4TllBTWtZCm1jQlcyWGdPTHEvQTg2dktyaTM4QU5vSGxrTjlyV3lKcERHZXoyanBIOXhBT3grOVJkK1d6enR0UjVIYjFTMlMKN01OdlI2T3lMZ3ZyaEN3L2JsQTB6a2h0akpQVkIwY2xUU3V5RmI5cEtrQkVVNGo1ZE13RUpLME80QVpZRkxUaApJYlEyTWc4bDBHcFpHZkRyZkZtSjBVeTFxZXZuM1B2a1VEeG0yR3RIRFFXK1pjeFZZOWQ5UEVvSW5pQnN6Rkt3Cm1kQUd1Q2xsQWdNQkFBR2pZekJoTUE0R0ExVWREd0VCL3dRRUF3SUNwREFQQmdOVkhSTUJBZjhFQlRBREFRSC8KTUIwR0ExVWREZ1FXQkJTdkltamVBR1NuUy9OdXNzL0svYTdUSDRhcFREQWZCZ05WSFNNRUdEQVdnQlN2SW1qZQpBR1NuUy9OdXNzL0svYTdUSDRhcFREQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFnd3dla3lDdGdSV1hFb2pOCjhjWCtKNFFPZ1h4andPeDZla1ordEhvUDJ1RThYd0dseWtCL015NW9vaEQvdkZwNFpjc3I5UWhyVFFtZVhvOUoKUHd0N0s3N1VuUXVURFU3YXp6dXhFc2VWdEZIUTVMUzZKYy9uL2RmT2pZc3ZWSmh0SjB6SVVuTW9IVVdYLzE4UApVRE1EOE1CR0trREdPMmF4OHR3REZKc0h4YUYwbVIwMHl1c0MwOUtnZ29xeDlFOVlEbUVNbGl3Z3IxcmRQQllICkxBbmphTEpFWkJDWHhBdTlBT1JDRzZBa2Z5Q2ErcmFDT3lybGg5dFllVC84VmFGZ29LVHpzdDRyMEZOSVlYaTUKT3NFZ0QrR3BwS2R0anE0cFRJK1QvODk1QWU0bDhTZkR4OVFpak1ZSHFqTXlvWXZzZmVkTTJGb1N3TkQ3aXA4RwpFbzF4SHc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDN1RDQ0FkV2dBd0lCQWdJQkFUQU5CZ2txaGtpRzl3MEJBUXNGQURBbU1TUXdJZ1lEVlFRRERCdHBibWR5ClpYTnpMVzl3WlhKaGRHOXlRREUxT0RFMk56SXhOell3SGhjTk1qQXdNakUwTURreU1qVTJXaGNOTWpJd01qRXoKTURreU1qVTNXakFtTVNRd0lnWURWUVFEREJ0cGJtZHlaWE56TFc5d1pYSmhkRzl5UURFMU9ERTJOekl4TnpZdwpnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDcFVFWm4vN1VPSkVjVDVhWEc5TUp4CmJ3VDVpd2RNRUwwUHFTTWkrRUJrV3AxN3VPT094RVZnbUYzSUVLZEk4bFJLZ0FJRXdSSldSMDRBU3o3bTRaYjUKNVNpRTg1NlNyb1h1SlhJblY0c3c1R2FqRXR1eDVyODRvZTc5Z1RKV0poaWtxOTl6TytUcENPQWtsdjVsYjdMTApmOHVXUVJxbU43MXc2OFV2WWF5WXJwMDdqVFJnai9pMUd0Wkh1WURSTTNPMG5lV2RSbGpUdjdxNDJTb2lxNmo4CnlpTmw1Mk1LTWhCMGlMOXM4Mk1KUjFDaEE4RjE1TkJKWWpScFhuMGlxTGkrWHlTNEVtTTRLcTFiVDU0RUlhZDQKdGNvendsNWJXRndlcVFYYWhqYm0yT2tPZGViRUZyY1dJd2dBRHAxQk9NSmYvYkdlVkQyajkrOHhtaVNISUF1WgpBZ01CQUFHakpqQWtNQTRHQTFVZER3RUIvd1FFQXdJQ3BEQVNCZ05WSFJNQkFmOEVDREFHQVFIL0FnRUFNQTBHCkNTcUdTSWIzRFFFQkN3VUFBNElCQVFDU1JpemVqVFc1MzNZMitTVmVyVWRLOGVSVUovMDlhczZaN3ZMNW85K0kKNS9mV2lrbUJzamFJQjhDb1o2UC9VZk1mSWsvNGx3cFRvWXI5QXMraW9zNVlULy9LVGl0THdZOXJPWW56UlM0RQo3WGt0VnB4T0xYVGpDa3dvQS9NQThPRi9QZE9ELzZwby90aG9rc2ZmMWV3NkJ1US9TaURGQ1k1MzNKUVZ5TDgxCmx2RXBNa2tRNzdNRXhuNWovVlgwMDJtcGdRZlhZcVFOaHpwQTRtbm5QZ2QvWElpL2FtYVB1UTJXSTlDVXhpeEwKMmdhUTQrZ015OUFuVFVVVnFSQ0UxNjhnOWN6bzNSdE1mSFZzNldEeFNhU1AxaUE4cFlLQldOQ2FrM0VYMnBEYgovV2hCdUw5dlRmWUF4d0tvZjhvL2RhbHBqSmtqK29oNEVmVmNlMmhKcVJVcgotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    server: https://api-int.iacopo-cluster.aws.loodse.dev:6443
  name: local
contexts:
- context:
    cluster: local
    user: kubelet
  name: kubelet
current-context: kubelet
preferences: {}
users:
- name: kubelet
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IjJfOUN3cGFTOHd0T2ltWnRJT2hqYi1WSjBJMndqU2JGSnRWMktKUmdjREEifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJvcGVuc2hpZnQtbWFjaGluZS1jb25maWctb3BlcmF0b3IiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoibm9kZS1ib290c3RyYXBwZXItdG9rZW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoibm9kZS1ib290c3RyYXBwZXIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiI2YmE1N2RiYi01NmU2LTRlY2UtOGY1ZS1lYWI3MzA1NzIzNDUiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6b3BlbnNoaWZ0LW1hY2hpbmUtY29uZmlnLW9wZXJhdG9yOm5vZGUtYm9vdHN0cmFwcGVyIn0.C29lwr559fLbUUftwNX-9AhoZiEsRpyCebK_vPB7kWCTHRW1aNIOj9RBOwJkI3asqS54lK6bgiaEro7tvobQt0XX0UKXnkZFC-hzttlUS-1RCQc7wYw9Db4hNLtMTvhcQixsdCs2GsfIbBfI3pEYEKQZPPCROD_THkE2JOuoR3ulOVI11m_ws0VwrGJiLP3mlXlnLvP6MY8Mc-D8FwcN7dLos6E2QG0a7R40SUo-SWgtwBSciUM1S7BQ9lzdCukdyVIJBOo_vu7_3itAgdxFDqw4mzK0zuZ9nCZo2GdNWgv1cm5NeSOwgCReG00lm6QKEePrhTx3TwcGCILqQr-RcQ`

func TestGenerateIgnitionForRole(t *testing.T) {
	type args struct {
		config      *RenderConfig
		role        string
		templateDir string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Whao",
			args: args{
				config: &RenderConfig{
					Platform: "vsphere",
				},
				role:        "worker",
				templateDir: "templates",
			},
			want:    "",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateIgnitionForRole(tt.args.config, defaultConfig(&RenderConfig{Kubeconfig: kubeconfig}, []string{"ssh-rsa AAAAB3Nza..."}), tt.args.role, tt.args.templateDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateIgnitionForRole() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			m, err := json.Marshal(got)
			if err != nil {
				t.Errorf("Error marshaling ignition configuration: %v", m)
			}
			if string(m) != tt.want {
				t.Errorf("GenerateIgnitionForRole() = %v, want %v", string(m), tt.want)
			}
		})
	}
}
