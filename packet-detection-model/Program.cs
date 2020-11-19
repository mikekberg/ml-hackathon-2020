using System;
using System.IO;
using Kaitai;
using packet_detection_model.models.BadAgentModel;
using CommandLine;
using System.Text.RegularExpressions;
using CommandLine.Text;

namespace packet_detection_model
{
    class Program
    {
        public class CLIOptions
        {
            [Option('a', "action", Required = true)]
            public string Action { get; set; }
            [Option('d', "dataDir", HelpText="The folder to find the data files.")]
            public string DataDir { get; set; }
            [Option('o', "output", HelpText="The output file for the processed data.")]
            public string Output { get; set; }
            [Option('p', "portsFile", HelpText="The file containing a list of ports to limit the data to.")]
            public string PortsFile { get; set; }
            [Option('v', "dataview", HelpText="The file containing processed data from the prepdata command")]
            public string dataView { get; set; }
            [Option('m', "modeloutput", HelpText="The output to save the model to after training")]
            public string ModelOutput { get; set; }
            [Option("model", HelpText = "The output to save the model to after training")]
            public string Model { get; set; }
        }

        static void Main(string[] args)
        {
            Parser
                .Default
                .ParseArguments<CLIOptions>(args)
                .WithParsed<CLIOptions>(o =>
                {
                    var pd = new BadAgentModel();

                    switch (o.Action)
                    {
                        case "prepsummarydata":
                            pd.ProcessSummaryData(Directory.GetFiles(o.DataDir, "*.cap"), (o.Output ?? "ParsedPacketData.bin"), (o.PortsFile ?? "common-ports.csv"));
                            break;

                        case "trainsummarymodel":
                            pd.TrainSummaryModel(o.dataView, o.Model);
                            break;

                        case "detectmalips":
                            var malIps = pd.DetectMalicousIps(Directory.GetFiles(o.DataDir, "*.cap"), (o.PortsFile ?? "common-ports.csv"), o.Model);

                            Console.WriteLine($"\nDetected {malIps.Length} Malicious Ips: ");
                            foreach (var ip in malIps)
                            {
                                Console.WriteLine(ip);
                            }

                            break;

                        case "preppacketdata":
                            pd.ProcessPacketData(Directory.GetFiles(o.DataDir, "*.cap"), (o.Output ?? "ParsedPacketData.bin"));
                            break;

                        case "trainsinglepacketmodel":
                            pd.TrainSinglePacketModel(o.dataView, o.ModelOutput);
                            break;

                        default:
                            Console.WriteLine("Unable to find command");
                            break;
                    }
                });
        }
    }
}
