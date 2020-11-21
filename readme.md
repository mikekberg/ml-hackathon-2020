# ML.NET 2020 Hackathon Submission - 1st Place

Full Video Explaining the the approach can be found here: 

https://www.youtube.com/watch?v=c-IhpiQPVfA&ab_channel=MikeBerg


## How to run the solution

### Step 1 - Generate Packet Data

To run this you will need labeled packet data, this can either be generated using the docker scripts inside the [data-generation](/data-generation) folder or you can
import data of your own using a tool like tcpdump or wireshark on windows. This packet data need to follow a naming convension so the process to properly label the convension is:

{Name}.{Ip}.{U|M}.cap   (Exmaple: 'Bob1.192-168-1-3.U.cap')

**Name**: Name of the agent. This can be anything its not used by the system and just helpful to keep track of the files
***Ip**: Inernal IP of the agent. **With dots replaced with dashes**
**U | M**: If the agent is Malicous then **M** else **U** for normal agent


If you want to generate your own data, take a look at the data-generation folder. Chuck and Charlie are example of agents that generate malicous traffic and Bob generates normal traffic, run this process by creating a folder called "packet-data" in the dataa-generation folder (this is an empty folder used in the docker-compose to dump the packet capture files to) then run

`docker-compose up`

### Step 2 - Packet Summarization

Now that you have the packet data you need to have it summarized. To do this build the soluition file in the rool and run the `packet-detection-model.exe` executable created. Running without command line argument will give you the help text. The command to run summarization is:

`packet-detection-model.exe -a prepsummarydata --dataDir .\training-data\ --output SummaryData.bin --portsFile .\common-ports.csv`

This assumes you have a folder called `training-data` in the same folder as the exec with the cap files described above. [common-ports.csv](./packet-detection-model/common-ports.csv) has a list of the ports to use for summarization, all other port data is dropped. This command will save the summary data to `SummaryData.bin`

### Step 3 - Train the Model

To traing the model on the summarized data run the following:

`packet-detection-model.exe -a trainsummarymodel --dataview .\SummaryData.bin --model .\SummaryModel.zip`


### Step 4 - Run the model on new traffic

Now that the model is trained you can run it on new network data, to run on new network data run the following:

`packet-detection-model.exe -a detectmalips --dataDir .\training-data\ --portsFile .\common-ports.csv --model .\SummaryModel.zip`


