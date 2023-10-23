package imagevector

import (
	"github.com/gardener/gardener/pkg/utils/imagevector"
	"k8s.io/apimachinery/pkg/util/runtime"

	"github.com/metal-stack/gardener-extension-audit/charts"
)

var imageVector imagevector.ImageVector

func init() {
	var err error

	imageVector, err = imagevector.Read([]byte(charts.ImagesYAML))
	runtime.Must(err)

	imageVector, err = imagevector.WithEnvOverride(imageVector)
	runtime.Must(err)
}

// ImageVector is the image vector that contains all the needed images.
func ImageVector() imagevector.ImageVector {
	return imageVector
}
