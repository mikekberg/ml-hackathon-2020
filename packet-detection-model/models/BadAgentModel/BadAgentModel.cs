using Kaitai;
using Microsoft.ML;
using Microsoft.ML.Data;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace packet_detection_model.models.BadAgentModel
{
    public class BadAgentModel
    {
        private static TraceSource ts = new TraceSource("BadAgentModelTrace");

        private SchemaDefinition getSummarySchemaDefinition(int ports)
        {
            var schema = SchemaDefinition.Create(typeof(SummaryPacketData));
            var featureColumn = schema["PortData"];
            var itemType = ((VectorDataViewType)featureColumn.ColumnType).ItemType;
            featureColumn.ColumnType = new VectorDataViewType(itemType, ports * 4);

            return schema;
        }

        private SchemaDefinition getSinglePacketSchemaDefinition(int packetSize)
        {
            var schema = SchemaDefinition.Create(typeof(LabeledPacketData));
            var featureColumn = schema["PacketBody"];
            var itemType = ((VectorDataViewType)featureColumn.ColumnType).ItemType;
            featureColumn.ColumnType = new VectorDataViewType(itemType, packetSize);

            return schema;
        }

        public void ProcessSummaryData(string[] packetFiles, string output = "ParsedPacketData.bin", string portsFile = "common-ports.csv")
        {
            var commonPorts = File.ReadAllLines(portsFile).Select(x => int.Parse(x)).ToArray();
            var maliciousIps = packetFiles.Select(x => x.Split('\\').Last()).Where(x => x.Contains(".M.")).Select(x => x.Split('.')[1].Replace('-', '.')).ToArray();

            MLContext mlContext = new MLContext();

            var packetData = this.PrepareSummaryData(packetFiles, commonPorts, maliciousIps);
            var dataView = mlContext.Data.LoadFromEnumerable(packetData, getSummarySchemaDefinition(commonPorts.Length));

            using (var stream = File.Create(output)) {
                mlContext.Data.SaveAsBinary(dataView, stream);
            }
        }

        public string[] DetectMalicousIps(string[] packetFiles, string portsFile, string model)
        {
            MLContext mlContext = new MLContext();
            DataViewSchema schema;
            var mlModel = mlContext.Model.Load(model, out schema);

            var commonPorts = File.ReadAllLines(portsFile).Select(x => int.Parse(x)).ToArray();
            var processedData = this.PrepareSummaryData(packetFiles, commonPorts, null);

            var predictionEngine = mlContext.Model.CreatePredictionEngine<SummaryPacketData, SummaryPacketPrediction>(mlModel, schema);

            var malPredictions = processedData.Select(x => (prediction: predictionEngine.Predict(x), packetWindow: x));
            var totalPredictions = malPredictions.Count();

            var malGroups = malPredictions
                .GroupBy(x => x.packetWindow.Ip)
                .Select(x => (x.Key, x.Count(), x.Count(y => y.prediction.IsMalicious)));
          
            Console.WriteLine($"\n=============== Detected {malPredictions.Count()} Malicious Packet Frames ===============\n");

            foreach (var group in malGroups)
            {
                Console.WriteLine($"IP - {group.Key}, Total: {group.Item2}, Malicous: {group.Item3} ({Math.Round((float)group.Item3 / (float)group.Item2, 2)})");
            }

            Console.WriteLine();

            return malGroups
                .Where(x => (x.Item3 / x.Item2) > 0.15 )
                .Select(x => x.Key)
                .Distinct()
                .ToArray();
        }

        public void ProcessPacketData(string[] packetFiles, string output = "ParsedPacketData.bin")
        {
            var maliciousIps = packetFiles.Select(x => x.Split('\\').Last()).Where(x => x.Contains(".M.")).Select(x => x.Split('.')[1].Replace('-', '.')).ToArray();

            MLContext mlContext = new MLContext();

            var packetData = this.PrepareSinglePacketData(packetFiles, maliciousIps);
            var dataView = mlContext.Data.LoadFromEnumerable(packetData, getSinglePacketSchemaDefinition(packetData.First().PacketBody.Length));

            using (var stream = File.Create(output))
            {
                mlContext.Data.SaveAsBinary(dataView, stream);
            }
        }

        public void TrainSinglePacketModel(string binData, string output = "BadAgentSinglePacketModel.zip")
        {
            MLContext mlContext = new MLContext();
            var modelData = mlContext.Data.LoadFromBinary(binData);
            var splitDataView = mlContext.Data.TrainTestSplit(modelData);

            var estimator = mlContext.Transforms.DropColumns("SrcIp")
                .Append(mlContext.Transforms.Conversion.ConvertType("PacketBody", "PacketBody"))
                .Append(mlContext.BinaryClassification.Trainers.SdcaLogisticRegression(labelColumnName: "IsMalicious", featureColumnName: "PacketBody"));

            Console.WriteLine("=============== Create and Train the Model ===============");
            var model = estimator.Fit(splitDataView.TrainSet);
            Console.WriteLine("=============== End of training ===============");
            Console.WriteLine();

            Evaluate(mlContext, model, splitDataView.TestSet, "PacketBodySingle");

            using (var stream = File.Create(output))
            {
                mlContext.Model.Save(model, modelData.Schema, stream);
            }

        }

        public void TrainSummaryModel(string binData, string output= "SummaryModel.zip")
        {
            MLContext mlContext = new MLContext();
            var modelData = mlContext.Data.LoadFromBinary(binData);
            var splitDataView = mlContext.Data.TrainTestSplit(modelData, 0.4);

            var estimator = mlContext.Transforms.DropColumns("Ip")
                .Append(mlContext.BinaryClassification.Trainers.SdcaLogisticRegression(labelColumnName: "IsMalicious", featureColumnName: "PortData"));

            Console.WriteLine("=============== Create and Train the Model ===============");
            var model = estimator.Fit(splitDataView.TrainSet);
            Console.WriteLine("=============== End of training ===============");
            Console.WriteLine();

            Evaluate(mlContext, model, splitDataView.TestSet, "IsMalicious");

            using (var stream = File.Create(output))
            {
                mlContext.Model.Save(model, modelData.Schema, stream);
            }            
        }

        public void Evaluate(MLContext mlContext, ITransformer model, IDataView splitTestSet, string labelColumn)
        {
            // This code was taken from the linear regession demo on the ML.NET github page

            // Evaluate the model and show accuracy stats

            //Take the data in, make transformations, output the data.
            // <SnippetTransformData>
            Console.WriteLine("=============== Evaluating Model accuracy with Test data===============");
            IDataView predictions = model.Transform(splitTestSet);
            // </SnippetTransformData>

            // BinaryClassificationContext.Evaluate returns a BinaryClassificationEvaluator.CalibratedResult
            // that contains the computed overall metrics.
            // <SnippetEvaluate>
            CalibratedBinaryClassificationMetrics metrics = mlContext.BinaryClassification.Evaluate(predictions, labelColumn);
            // </SnippetEvaluate>

            // The Accuracy metric gets the accuracy of a model, which is the proportion
            // of correct predictions in the test set.

            // The AreaUnderROCCurve metric is equal to the probability that the algorithm ranks
            // a randomly chosen positive instance higher than a randomly chosen negative one
            // (assuming 'positive' ranks higher than 'negative').

            // The F1Score metric gets the model's F1 score.
            // The F1 score is the harmonic mean of precision and recall:
            //  2 * precision * recall / (precision + recall).

            // <SnippetDisplayMetrics>
            Console.WriteLine();
            Console.WriteLine("Model quality metrics evaluation");
            Console.WriteLine("--------------------------------");
            Console.WriteLine($"Accuracy: {metrics.Accuracy:P2}");
            Console.WriteLine($"Auc: {metrics.AreaUnderRocCurve:P2}");
            Console.WriteLine($"F1Score: {metrics.F1Score:P2}");
            Console.WriteLine("\n=============== End of model evaluation ===============");
            //</SnippetDisplayMetrics>
        }

        private IEnumerable<LabeledPacketData> PrepareSinglePacketData(string[] packetFiles, string[] maliciousIps)
        {
            Stopwatch stopwatch = new Stopwatch();
            Console.WriteLine("=============== Preparing Single Packet Data ===============");
            Console.WriteLine();
            Console.WriteLine($"Start data prep using {packetFiles.Length} packet files, {maliciousIps.Length} malicious Ips.");
            Console.WriteLine($"Files Being Processed:");

            foreach (var file in packetFiles)
            {
                Console.WriteLine($"\t{file}");
            }

            stopwatch.Start();

            var ipv4Packets = packetFiles
                .SelectMany(x => Pcap.FromFile(x).Packets)
                .Where(x => x.Body is EthernetFrame && ((EthernetFrame)x.Body).EtherType == EthernetFrame.EtherTypeEnum.Ipv4)
                .Select(x => (TimeStamp: x.TsSec, Packet: ((Ipv4Packet)((EthernetFrame)x.Body).Body)))
                .ToArray();

            var largestPacketSize = ipv4Packets.Max(x => x.Packet.M_RawBody.Length);

            Console.WriteLine($"Largest Packet Size: {largestPacketSize} bytes.");

            var packets = ipv4Packets
                .Select(x =>
                {
                    var labeledPacket = new LabeledPacketData()
                    {
                        SrcIp = x.Packet.SrcIpAddrStr,
                        IsMalicious = maliciousIps.Contains(x.Packet.SrcIpAddrStr),
                        PacketLength = x.Packet.M_RawBody.Length,
                        PacketBody = new byte[largestPacketSize]
                    };

                    Array.Copy(x.Packet.M_RawBody, labeledPacket.PacketBody, x.Packet.M_RawBody.Length);

                    return labeledPacket;
                });


            stopwatch.Stop();
            Console.WriteLine("Time elapsed: {0}", stopwatch.Elapsed);
            Console.WriteLine("=============== End of data prep ===============");


            return packets;
        }

        private IEnumerable<SummaryPacketData> PrepareSummaryData(string[] packetFiles, int[] includedPorts, int windowSize = 5)
        {
            return PrepareSummaryData(packetFiles, includedPorts, null, windowSize);
        }

        private IEnumerable<SummaryPacketData> PrepareSummaryData(string[] packetFiles, int[] includedPorts, string[] maliciousIps, int windowSize = 5)
        {
            Stopwatch stopwatch = new Stopwatch();
            Console.WriteLine("=============== Preparing Summary Window Packet Data ===============");
            Console.WriteLine();
            Console.WriteLine($"Start data prep using {packetFiles.Length} packet files, {includedPorts.Length} included ports, {maliciousIps?.Length ?? 0} malicious Ips and window size of {windowSize} seconds.");
            Console.WriteLine($"Files Being Processed:");

            foreach (var file in packetFiles)
            {
                Console.WriteLine($"\t{file}");
            }

            stopwatch.Start();

            var ipv4Packets = packetFiles
                .SelectMany(x => Pcap.FromFile(x).Packets)
                .Where(x => x.Body is EthernetFrame && ((EthernetFrame)x.Body).EtherType == EthernetFrame.EtherTypeEnum.Ipv4)
                .Select(x => (TimeStamp: x.TsSec, Packet: ((Ipv4Packet)((EthernetFrame)x.Body).Body)))
                .ToArray();

            Console.WriteLine($"Done Extracting Packets for cap files. Found {ipv4Packets.Length} IPv4 packets");

            var dataTimeSpan = (Min: ipv4Packets.Select(x => x.TimeStamp).Min(), Max: ipv4Packets.Select(x => x.TimeStamp).Max());
            var totalWindows = Math.Ceiling((float) ((dataTimeSpan.Max - dataTimeSpan.Min) / windowSize));

            Console.WriteLine($"Date time range for packets is {dataTimeSpan.Min} - {dataTimeSpan.Max} ({totalWindows} total window chunks)");

            var uniqueIps = ipv4Packets
                .SelectMany(x => new[] { x.Packet.SrcIpAddrStr, x.Packet.DstIpAddrStr })
                .Distinct();

            Console.WriteLine($"{uniqueIps.Count()} unique IP's found in the data. Starting packet summarization");

            var data = ipv4Packets
                .GroupBy((x => (x.TimeStamp - dataTimeSpan.Min - ((x.TimeStamp - dataTimeSpan.Min) % windowSize)) / windowSize))
                .AsParallel()
                .SelectMany(window =>
                    window
                        .SelectMany(x => new[] { x.Packet.SrcIpAddrStr, x.Packet.DstIpAddrStr })
                        .Distinct()
                        .AsParallel()
                        .Select(ip =>
                        {
                            var packetData = window.Where(x => x.Packet.DstIpAddrStr == ip || x.Packet.SrcIpAddrStr == ip);
                            var portData = includedPorts.SelectMany(x =>
                            {
                                var portPackets = packetData.Where(y => Convert.ToInt32(y.Packet.Protocol) == x);

                                return portPackets.Any() ? new[]
                                {
                                        (float)x,
                                        ((float) portPackets.Average(p => p.Packet.TotalLength)),
                                        (float)portPackets.Where(p => p.Packet.DstIpAddrStr == ip).Count(),
                                        (float)portPackets.Where(p => p.Packet.SrcIpAddrStr == ip).Count()
                                    } : new[] { 0.0f, 0.0f, 0.0f, 0.0f };
                            }).ToArray();

                            return (packetData.Count() == 0 || portData.Sum() == 0) ? null : new SummaryPacketData()
                            {
                                WindowSize = windowSize,
                                Ip = ip,
                                IsMalicious = maliciousIps != null ? maliciousIps.Contains(ip) : false,
                                PortData = portData
                            };
                         })
                  )
                .Where(x => x != null)
                .ToArray();

            if (maliciousIps != null)
            {
                var malIps = data.Where(x => x.IsMalicious).Count();
                Console.WriteLine($"Data summarization done, Labels found. {malIps} packet windows out of {data.Count()} labels as malicious.");
            }

            stopwatch.Stop();
            Console.WriteLine("Time elapsed: {0}", stopwatch.Elapsed);
            Console.WriteLine("=============== End of data prep ===============");

            return data;
        }
    }
}
