    action(type="omhiredis"
           name="{{output_name}}"
           server="{{target}}"
           serverport="{{port}}"
           mode="queue"
           key="{{key}}"
           ServerPassword="{{pwd}}"
           Template="{{ out_template }}"
           )
