using Microsoft.ML.Data;
using System;
using System.Collections.Generic;
using System.Text;

namespace packet_detection_model.models.BadAgentModel
{
    class SummaryPacketPrediction
    {
        [ColumnName("PredictedLabel")]
        public bool IsMalicious { get; set; } = false;
    }
}
