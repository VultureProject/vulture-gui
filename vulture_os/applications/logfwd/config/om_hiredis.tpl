    action(type="omhiredis"
           name="{{output_name}}"
           server="{{target}}"
           serverport="{{port}}"
           mode="{{mode}}"
           key="{{key}}"
           ServerPassword="{{pwd}}"
           Template="{{ out_template }}_redis")
